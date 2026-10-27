"""Điểm vào chương trình quét cổng TCP."""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import sys
import time
from datetime import datetime
from pathlib import Path

from report import ScanRecord, write_report
from scanner import discover_hosts, scan_targets
from services import get_service_name


# Các dải IP nội bộ được phép quét theo quy định an toàn của dự án.
_INTERNAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)

# Dải CIDR lớn nhất được phép: /18 (16382 host khả dụng). Lớn hơn /18 bị từ chối
# ngay, không có cờ nào bỏ qua.
CIDR_MIN_PREFIX = 18

# Hai mốc giới hạn áp dụng cho TỪNG giai đoạn của một lần quét. Mỗi giai đoạn
# được đánh giá độc lập, không cộng dồn lượt của giai đoạn này với giai đoạn kia.
# - vượt WARN_ATTEMPTS: phải xác nhận thêm (--confirm-large-scan, hoặc confirm
#   trên web) mới chạy giai đoạn đó.
# - vượt HARD_ATTEMPTS: từ chối hẳn, không có cách nào vượt qua.
WARN_ATTEMPTS = 500_000
HARD_ATTEMPTS = 5_000_000

# Số luồng song song tối đa cho mỗi giai đoạn. Mặc định vẫn là 100; người dùng
# có thể nâng tới 10.000 luồng khi cần quét rất nhanh trên máy đủ mạnh.
MAX_CONCURRENCY = 10_000
DEFAULT_CONCURRENCY = 100
# Vượt mốc này thì cảnh báo (không chặn): mỗi luồng giữ một cổng tạm
# (ephemeral port) trên máy nên số luồng quá lớn có thể làm cạn cổng tạm.
CONCURRENCY_WARN = 2_000

# Tên hai giai đoạn của một lần quét CIDR. Mục tiêu là một IP đơn chỉ có giai
# đoạn quét cổng.
STAGE_DISCOVERY = "discovery"
STAGE_SCAN = "scan"
STAGE_LABELS = {
    STAGE_DISCOVERY: "giai đoạn dò host sống",
    STAGE_SCAN: "giai đoạn quét cổng",
}

# Hai subcommand của CLI. Hai giai đoạn chạy tách rời nên `scan` không tự dò CIDR.
SUBCOMMANDS = ("discover", "scan")

# Thông báo khi người dùng còn truyền CIDR thẳng vào `scan`.
SCAN_CIDR_HINT = (
    "scan không còn tự dò CIDR, hãy chạy 'main.py discover <CIDR>' trước rồi "
    "dùng --hosts-file hoặc --hosts với danh sách host thu được."
)

# Khóa chứa danh sách host sống trong file JSON do `discover` tạo ra.
LIVE_HOSTS_KEY = "live_hosts"


def count_target_hosts(
    target: ipaddress.IPv4Address | ipaddress.IPv4Network,
) -> int:
    """Số host tối đa của mục tiêu, dùng để ước tính trước khi dò host sống."""
    if isinstance(target, ipaddress.IPv4Network):
        return sum(1 for _ in target.hosts())
    return 1


def estimate_stage_attempts(hosts: int, ports_count: int) -> int:
    """Số lượt của MỘT giai đoạn = số host × số cổng của riêng giai đoạn đó.

    Không bao giờ cộng lượt dò host với lượt quét cổng: mỗi giai đoạn được so
    sánh với hai mốc bằng chính con số của nó.
    """
    return hosts * ports_count


def estimate_stage_seconds(
    hosts: int,
    ports_count: int,
    timeout: float,
    workers: int = 1,
) -> float:
    """Ước tính thời gian của MỘT giai đoạn, tính bằng giây.

    Mỗi lượt thử chờ tối đa `timeout` giây và có `workers` luồng chạy song song,
    nên đây là ước lượng trường hợp xấu nhất (mọi kết nối đều hết thời gian chờ).
    """
    return hosts * ports_count * timeout / max(1, workers)


def format_attempts(value: int) -> str:
    """Định dạng số lượt theo kiểu Việt Nam (dấu chấm ngăn nghìn)."""
    return f"{value:,}".replace(",", ".")


def format_duration(seconds: float) -> str:
    """Đổi số giây thành câu tiếng Việt dễ đọc."""
    if seconds < 60:
        return f"{seconds:.0f} giây"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.0f} phút"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.1f} giờ"
    return f"{hours / 24:.1f} ngày"


def stage_limit_message(stage: str, hosts: int, ports_count: int) -> str:
    """Thông báo khi MỘT giai đoạn vượt trần cứng số lượt quét."""
    attempts = estimate_stage_attempts(hosts, ports_count)
    if stage == STAGE_DISCOVERY:
        hint = "Hãy giảm số cổng dò host hoặc thu nhỏ dải CIDR."
    else:
        hint = "Hãy giảm số cổng hoặc bớt host trong danh sách cần quét."
    return (
        f"Vượt trần cứng {format_attempts(HARD_ATTEMPTS)} lượt ở "
        f"{STAGE_LABELS[stage]}: ước tính {format_attempts(attempts)} lượt "
        f"({hosts} host × {ports_count} cổng). {hint}"
    )


def stage_warning_lines(stage: str, attempts: int, seconds: float) -> list[str]:
    """Các dòng cảnh báo khi MỘT giai đoạn vượt mốc phải xác nhận."""
    return [
        f"CẢNH BÁO: {STAGE_LABELS[stage]} ước tính "
        f"{format_attempts(attempts)} lượt, vượt mốc "
        f"{format_attempts(WARN_ATTEMPTS)} lượt.",
        f"Thời gian ước tính khoảng {format_duration(seconds)} "
        "(theo timeout và số luồng hiện tại).",
        "Quét dải lớn có thể làm chậm mạng và dễ bị hệ thống an ninh phát hiện.",
    ]


def concurrency_warning_lines(workers: int) -> list[str]:
    """Cảnh báo khi số luồng vượt mốc an toàn; KHÔNG chặn chạy.

    Mỗi luồng giữ một kết nối TCP đang mở nên chiếm một cổng tạm của máy. Số
    luồng quá lớn có thể làm cạn dải cổng tạm (ephemeral ports) và khiến cả
    chính chương trình lẫn ứng dụng khác không mở được kết nối mới.
    """
    if workers <= CONCURRENCY_WARN:
        return []
    return [
        f"CẢNH BÁO: {format_attempts(workers)} luồng song song, vượt mốc "
        f"{format_attempts(CONCURRENCY_WARN)} luồng.",
        "Mỗi luồng giữ một cổng tạm trên máy; quá nhiều luồng có thể làm cạn "
        "cổng tạm và khiến kết nối mới thất bại.",
        "Chương trình vẫn tiếp tục chạy, chỉ cảnh báo để bạn cân nhắc.",
    ]


def warn_high_concurrency(workers: int) -> None:
    """In cảnh báo số luồng cao (nếu có)."""
    for line in concurrency_warning_lines(workers):
        print(line)


def concurrency_value(value: str) -> int:
    """Kiểu tham số cho số luồng: số nguyên từ 1 đến MAX_CONCURRENCY."""
    return positive_int(value, maximum=MAX_CONCURRENCY)


def configure_output_encoding() -> None:
    """Ép stdout/stderr dùng UTF-8 để in tiếng Việt trên Windows."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")


def stdin_is_interactive() -> bool:
    """Kiểm tra stdin có phải terminal thật để quyết định có thể hỏi người dùng."""
    if sys.stdin is None:
        return False
    try:
        if not sys.stdin.isatty():
            return False
    except (AttributeError, OSError):
        return False

    if sys.platform == "win32":
        # Windows coi NUL là character device nên isatty() vẫn trả True.
        # GetConsoleMode phân biệt được console thật với NUL hoặc pipe.
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.GetStdHandle.argtypes = [ctypes.c_int]
            kernel32.GetStdHandle.restype = ctypes.c_void_p
            kernel32.GetConsoleMode.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_uint),
            ]
            kernel32.GetConsoleMode.restype = ctypes.c_int

            handle = kernel32.GetStdHandle(-10)
            mode = ctypes.c_uint()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
        except (AttributeError, OSError):
            return False

    return True


def parse_target(value: str) -> ipaddress.IPv4Address | ipaddress.IPv4Network:
    """Kiểm tra tham số mục tiêu là IPv4 hoặc CIDR IPv4 từ /18 đến /32."""
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != 4:
                raise argparse.ArgumentTypeError("hiện chỉ hỗ trợ địa chỉ IPv4")
            if network.prefixlen < CIDR_MIN_PREFIX:
                raise argparse.ArgumentTypeError(
                    f"chỉ hỗ trợ dải CIDR từ /{CIDR_MIN_PREFIX} đến /32; "
                    f"dải lớn hơn /{CIDR_MIN_PREFIX} bị từ chối"
                )
            return network

        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"địa chỉ IP/CIDR không hợp lệ: {value!r}"
        ) from exc

    if ip.version != 4:
        raise argparse.ArgumentTypeError("hiện chỉ hỗ trợ địa chỉ IPv4")
    return ip


def parse_ports(value: str) -> list[int]:
    """Phân tích dải cổng: '80', '1-1024' hoặc '22,80,443'."""
    ports: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            raise argparse.ArgumentTypeError("dải cổng không được để trống")

        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2:
                raise argparse.ArgumentTypeError(f"dải cổng không hợp lệ: {part!r}")
            try:
                start, end = int(bounds[0]), int(bounds[1])
            except ValueError as exc:
                raise argparse.ArgumentTypeError(
                    f"dải cổng không hợp lệ: {part!r}"
                ) from exc
            if not (1 <= start <= end <= 65535):
                raise argparse.ArgumentTypeError(
                    f"dải cổng phải trong khoảng 1-65535: {part!r}"
                )
            ports.extend(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(
                    f"cổng không hợp lệ: {part!r}"
                ) from exc
            if not 1 <= port <= 65535:
                raise argparse.ArgumentTypeError(
                    f"cổng phải trong khoảng 1-65535: {part!r}"
                )
            ports.append(port)

    # Loại bỏ cổng trùng nhưng giữ nguyên thứ tự người dùng nhập.
    return list(dict.fromkeys(ports))


def positive_float(value: str) -> float:
    """Kiểm tra timeout là số thực hữu hạn lớn hơn 0."""
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout phải là một số") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("timeout phải là số dương hữu hạn")
    return number


def positive_int(value: str, maximum: int | None = None) -> int:
    """Kiểm tra số nguyên dương, có thể kèm trần ``maximum``."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("số luồng phải là số nguyên") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("số luồng phải lớn hơn 0")
    if maximum is not None and number > maximum:
        raise argparse.ArgumentTypeError(
            f"số luồng phải từ 1 đến {maximum:,} (đã nhận {number:,}); "
            "quá nhiều luồng có thể làm cạn cổng tạm của máy"
        )
    return number


def is_internal(
    target: ipaddress.IPv4Address | ipaddress.IPv4Network,
) -> bool:
    """Kiểm tra IP hoặc CIDR có nằm trong dải nội bộ được phép quét không."""
    if isinstance(target, ipaddress.IPv4Network):
        return any(target.subnet_of(network) for network in _INTERNAL_NETWORKS)
    return any(target in network for network in _INTERNAL_NETWORKS)


def confirm_external_target(
    target: ipaddress.IPv4Address | ipaddress.IPv4Network,
    assume_yes: bool = False,
) -> bool:
    """Cảnh báo và xin xác nhận trước khi quét mục tiêu ngoài dải nội bộ."""
    print(f"CẢNH BÁO: {target} không nằm trong dải IP nội bộ.")
    print("Công cụ này chỉ dùng để quét máy của bạn, mạng nhà bạn hoặc máy ảo lab.")
    print("Chỉ tiếp tục nếu bạn có quyền quét mục tiêu này.")

    if assume_yes:
        print("Đã tự xác nhận bằng --yes.")
        return True

    if not stdin_is_interactive():
        print("Cần --yes khi chạy không tương tác.")
        return False

    try:
        answer = input("Tiếp tục quét? [y/N]: ").strip().lower()
    except EOFError:
        print("\nKhông nhận được xác nhận; cần --yes khi chạy không tương tác.")
        return False
    except (KeyboardInterrupt, OSError):
        print("\nĐã hủy xác nhận.")
        return False
    return answer in {"y", "yes"}


def confirm_large_scan(
    stage: str,
    attempts: int,
    seconds: float,
    assume_confirm: bool = False,
) -> bool:
    """Cảnh báo và xin xác nhận khi MỘT giai đoạn vượt mốc WARN_ATTEMPTS."""
    for line in stage_warning_lines(stage, attempts, seconds):
        print(line)

    if assume_confirm:
        print("Đã tự xác nhận bằng --confirm-large-scan.")
        return True

    if not stdin_is_interactive():
        print("Cần --confirm-large-scan khi chạy không tương tác.")
        return False

    try:
        answer = input(f"Tiếp tục {STAGE_LABELS[stage]}? [y/N]: ").strip().lower()
    except EOFError:
        print("\nKhông nhận được xác nhận; cần --confirm-large-scan.")
        return False
    except (KeyboardInterrupt, OSError):
        print("\nĐã hủy xác nhận.")
        return False
    return answer in {"y", "yes"}


def enforce_stage_limits(
    stage: str,
    hosts: int,
    ports_count: int,
    timeout: float,
    workers: int,
    assume_confirm: bool,
) -> bool:
    """Kiểm tra hai mốc cho MỘT giai đoạn; trả False nếu phải dừng.

    Số host truyền vào là số THẬT của giai đoạn đó: với `discover` là số host tối
    đa của CIDR, với `scan` là số host có trong danh sách cần quét.
    """
    if hosts <= 0 or ports_count <= 0:
        return True

    attempts = estimate_stage_attempts(hosts, ports_count)
    if attempts > HARD_ATTEMPTS:
        print(f"LỖI: {stage_limit_message(stage, hosts, ports_count)}")
        return False

    if attempts > WARN_ATTEMPTS:
        seconds = estimate_stage_seconds(hosts, ports_count, timeout, workers)
        if not confirm_large_scan(
            stage, attempts, seconds, assume_confirm=assume_confirm
        ):
            print("Đã hủy.")
            return False
    return True


def parse_host(value: str) -> ipaddress.IPv4Address:
    """Kiểm tra một host là IPv4 hợp lệ và thuộc dải nội bộ.

    Khác với mục tiêu của `scan` (vẫn cảnh báo rồi hỏi xác nhận như trước), host
    trong danh sách bị từ chối hẳn nếu nằm ngoài dải nội bộ.

    Raises:
        ValueError: Khi host rỗng, là CIDR, không phải IPv4, hoặc ngoài dải nội bộ.
    """
    text = value.strip()
    if not text:
        raise ValueError("địa chỉ host không được để trống")
    if "/" in text:
        raise ValueError(
            f"danh sách host chỉ nhận từng địa chỉ IPv4, không nhận CIDR: {text!r}"
        )

    try:
        ip = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError(f"địa chỉ IPv4 không hợp lệ: {text!r}") from exc

    if ip.version != 4:
        raise ValueError("hiện chỉ hỗ trợ địa chỉ IPv4")
    if not is_internal(ip):
        raise ValueError(
            f"host ngoài dải nội bộ bị từ chối: {ip} "
            "(chỉ nhận 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)"
        )
    return ip


def parse_host_list(value: str) -> list[ipaddress.IPv4Address]:
    """Phân tích --hosts: danh sách IPv4 phân cách bằng dấu phẩy, loại trùng.

    Raises:
        ValueError: Khi có phần tử rỗng hoặc có host không hợp lệ.
    """
    hosts: list[ipaddress.IPv4Address] = []
    for part in value.split(","):
        if not part.strip():
            raise ValueError("danh sách host không được để trống")
        hosts.append(parse_host(part))
    return list(dict.fromkeys(hosts))


def load_hosts_file(path_value: str) -> list[ipaddress.IPv4Address]:
    """Đọc danh sách host từ file JSON do `discover` tạo ra.

    Raises:
        ValueError: Khi không đọc được file, JSON sai, hoặc host không hợp lệ.
    """
    path = Path(path_value)
    try:
        # utf-8-sig để đọc được cả file có BOM do Notepad trên Windows tạo ra.
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ValueError(f"không đọc được file host {path}: {exc}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"file host {path} không phải JSON hợp lệ: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"file host {path} phải là một đối tượng JSON")

    entries = data.get(LIVE_HOSTS_KEY)
    if not isinstance(entries, list) or not entries:
        raise ValueError(
            f"file host {path} thiếu danh sách '{LIVE_HOSTS_KEY}' không rỗng"
        )

    hosts: list[ipaddress.IPv4Address] = []
    for entry in entries:
        if not isinstance(entry, str):
            raise ValueError(
                f"file host {path}: mỗi host phải là chuỗi, gặp {type(entry).__name__}"
            )
        try:
            hosts.append(parse_host(entry))
        except ValueError as exc:
            raise ValueError(f"file host {path}: {exc}") from exc

    return list(dict.fromkeys(hosts))


def format_port_line(port: int, banner: str | None) -> str:
    """Định dạng một dòng kết quả cổng kèm tên dịch vụ và banner."""
    line = f"  {port}/tcp  {get_service_name(port)}"
    if banner:
        line += f"  |  {banner}"
    return line


def format_live_line(host: str, port: int, banner: str | None) -> str:
    """Dòng kết quả in ngay khi tìm thấy cổng mở (có tiền tố host)."""
    line = f"  {host}:{port}  {get_service_name(port)}"
    if banner:
        line += f"  |  {banner}"
    return line


def current_timestamp() -> str:
    """Trả về thời điểm hiện tại theo ISO 8601 kèm múi giờ."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def format_port_spec(ports: list[int]) -> str:
    """Rút gọn danh sách cổng thành dạng 1-1024 hoặc 22,80,443."""
    if not ports:
        return ""

    ordered = sorted(set(ports))
    parts: list[str] = []
    start = previous = ordered[0]
    for port in ordered[1:]:
        if port == previous + 1:
            previous = port
            continue
        parts.append(f"{start}-{previous}" if start != previous else str(start))
        start = previous = port
    parts.append(f"{start}-{previous}" if start != previous else str(start))
    return ",".join(parts)


def build_records(
    host: str,
    open_ports: list[int],
    banners: dict[int, str],
    scanned_at: str,
) -> list[ScanRecord]:
    """Tạo các bản ghi báo cáo cho một host."""
    return [
        ScanRecord(
            host=host,
            port=port,
            protocol="tcp",
            service=get_service_name(port),
            banner=banners.get(port),
            scanned_at=scanned_at,
        )
        for port in open_ports
    ]


def resolve_output_path(value: str) -> Path:
    """Chuẩn hóa đường dẫn báo cáo; tên file trơn được đặt trong reports/."""
    if not value.strip():
        raise ValueError("đường dẫn output không được để trống")
    if value.endswith(("/", "\\")):
        raise ValueError("đường dẫn output phải là file, không phải thư mục")

    path = Path(value)
    if path.exists() and path.is_dir():
        raise ValueError("đường dẫn output phải là file, không phải thư mục")
    if path.parent == Path("."):
        path = Path("reports") / path
    return path


def prepare_output_path(args: argparse.Namespace, kind: str) -> Path | None:
    """Chuẩn hóa đường dẫn --output và xử lý ghi đè.

    Trả về đường dẫn cần ghi, hoặc None khi đã in lỗi/người dùng từ chối ghi đè.
    """
    try:
        path = resolve_output_path(args.output)
    except ValueError as exc:
        print(f"Lỗi: {exc}")
        return None

    if not path.exists():
        return path

    if path.is_dir():
        print(f"Lỗi: đường dẫn {kind} là thư mục: {path}")
        return None

    if getattr(args, "force", False):
        print(f"Ghi đè {kind} (--force): {path}")
        return path

    print(f"File {kind} đã tồn tại: {path}")
    if not stdin_is_interactive():
        print("Cần --force khi chạy không tương tác để ghi đè.")
        return None
    try:
        answer = input("Ghi đè? [y/N]: ").strip().lower()
    except EOFError:
        print("\nKhông nhận được xác nhận; cần --force để ghi đè.")
        return None
    except (KeyboardInterrupt, OSError):
        print(f"\nĐã hủy ghi {kind}.")
        return None
    if answer not in {"y", "yes"}:
        print(f"Không ghi đè; {kind} không được tạo.")
        return None
    return path


def report_target_label(hosts: list[ipaddress.IPv4Address]) -> str:
    """Nhãn mục tiêu cho báo cáo: một IP, hoặc "N host" khi quét danh sách."""
    if len(hosts) == 1:
        return str(hosts[0])
    return f"{len(hosts)} host"


def build_report_metadata(
    hosts: list[ipaddress.IPv4Address],
    ports: list[int],
    records: list[ScanRecord],
    duration: float,
) -> dict:
    """Metadata báo cáo quét cổng, dùng chung cho CLI và web server.

    `target` giữ nguyên ý nghĩa cũ (nhãn hiển thị) để không phá định dạng đang
    dùng; `target_hosts` là danh sách host thật đã quét.
    """
    return {
        "target": report_target_label(hosts),
        "target_hosts": [str(host) for host in hosts],
        "hosts_count": len(hosts),
        "port_range": format_port_spec(ports),
        "total_open_ports": len(records),
        "scan_duration_seconds": round(duration, 3),
    }


def save_report_if_requested(
    args: argparse.Namespace,
    hosts: list[ipaddress.IPv4Address],
    ports: list[int],
    records: list[ScanRecord],
    duration: float,
) -> int:
    """Ghi báo cáo nếu có --output; trả về 0 nếu thành công hoặc không cần ghi."""
    if not args.output:
        return 0

    path = prepare_output_path(args, "báo cáo")
    if path is None:
        return 1

    metadata = build_report_metadata(hosts, ports, records, duration)

    try:
        write_report(path, args.report_format, records, metadata)
    except (OSError, ValueError) as exc:
        print(f"Lỗi: không thể ghi báo cáo {path}: {exc}")
        return 1

    print(f"Đã ghi báo cáo: {path}")
    return 0


def write_discovery_output(
    args: argparse.Namespace,
    network: ipaddress.IPv4Network,
    discovery_ports: tuple[int, ...],
    live_hosts: list[str],
) -> int:
    """Ghi JSON kết quả dò host nếu có --output; 0 nếu thành công hoặc không ghi."""
    if not args.output:
        return 0

    path = prepare_output_path(args, "kết quả dò host")
    if path is None:
        return 1

    payload = {
        "cidr": str(network),
        "discovery_ports": format_port_spec(list(discovery_ports)),
        "discovered_at": current_timestamp(),
        "live_hosts": list(live_hosts),
    }

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"Lỗi: không thể ghi {path}: {exc}")
        return 1

    print(f"Đã ghi danh sách host sống: {path}")
    print(
        "Dùng lại bằng: main.py scan --hosts-file "
        f"{path} --ports <dải cổng>"
    )
    return 0


def run_discover(args: argparse.Namespace) -> int:
    """Giai đoạn 1: chỉ dò host sống trong CIDR, KHÔNG quét cổng."""
    network: ipaddress.IPv4Network = args.cidr
    hosts = [str(host) for host in network.hosts()]
    discovery_ports = tuple(args.discovery_ports)

    # Giới hạn của riêng giai đoạn dò: số host tối đa × số cổng dò.
    if not enforce_stage_limits(
        STAGE_DISCOVERY,
        len(hosts),
        len(discovery_ports),
        args.discovery_timeout,
        args.concurrency,
        args.confirm_large_scan,
    ):
        return 1

    print(
        f"Đang dò host sống trong {network} "
        f"({len(hosts)} host, cổng dò {format_port_spec(list(discovery_ports))}, "
        f"timeout {args.discovery_timeout}s, {args.concurrency} luồng)..."
    )
    warn_high_concurrency(args.concurrency)

    def report_progress(done: int, total: int, host: str, is_alive: bool) -> None:
        status = "sống" if is_alive else "không phản hồi"
        print(f"[{done}/{total}] {host}: {status}")

    started = time.perf_counter()
    try:
        live_hosts = discover_hosts(
            hosts,
            ports=discovery_ports,
            timeout=args.discovery_timeout,
            workers=args.concurrency,
            on_progress=report_progress,
        )
    except KeyboardInterrupt:
        print("\nĐã hủy bởi người dùng.")
        return 130
    elapsed = time.perf_counter() - started

    print(
        f"\nTìm thấy {len(live_hosts)}/{len(hosts)} host sống "
        f"trong {elapsed:.2f} giây."
    )
    if live_hosts:
        print("Danh sách host sống:")
        for host in live_hosts:
            print(f"  {host}")
    else:
        print("Không có host nào phản hồi.")

    status = write_discovery_output(args, network, discovery_ports, live_hosts)
    return 1 if status != 0 else 0


def scan_hosts(
    hosts: list[ipaddress.IPv4Address],
    args: argparse.Namespace,
) -> int:
    """Giai đoạn 2 chạy một lượt: quét cổng trên mọi host, in kết quả ngay.

    Mọi cặp (host, cổng) được đưa vào cùng một thread pool, không chia lô và
    không chờ host này xong mới sang host khác. Nhờ vậy kết quả hiện ra ngay
    khi tìm thấy cổng mở và mọi luồng đều có việc cho tới cặp cuối cùng.
    """
    ports = args.ports
    host_texts = [str(host) for host in hosts]
    total = len(host_texts) * len(ports)
    if len(host_texts) == 1:
        print(
            f"Đang quét {host_texts[0]} với {len(ports)} cổng "
            f"(timeout {args.timeout}s, banner {args.banner_timeout}s, "
            f"{args.workers} luồng)..."
        )
    else:
        print(
            f"Đang quét {len(host_texts)} host với {len(ports)} cổng "
            f"(tổng {format_attempts(total)} lượt, timeout {args.timeout}s, "
            f"banner {args.banner_timeout}s, {args.workers} luồng)..."
        )
    warn_high_concurrency(args.workers)

    open_by_host: dict[str, list[tuple[int, str | None]]] = {
        host_text: [] for host_text in host_texts
    }
    started = time.perf_counter()

    def report_result(host_text: str, port: int, banner: str | None) -> None:
        # In ngay để người dùng thấy tiến độ, không đợi hết lượt quét.
        open_by_host[host_text].append((port, banner))
        print(format_live_line(host_text, port, banner), flush=True)

    try:
        _, errors = scan_targets(
            ((host_text, port) for host_text in host_texts for port in ports),
            total=total,
            workers=args.workers,
            timeout=args.timeout,
            banner_timeout=args.banner_timeout,
            on_result=report_result,
        )
    except KeyboardInterrupt:
        print("\nĐã hủy bởi người dùng.")
        return 130
    elapsed = time.perf_counter() - started
    scanned_at = current_timestamp()

    if errors:
        print(f"\nCảnh báo: {len(errors)} cổng gặp lỗi mạng, ví dụ:")
        for host_text, port, message in errors[:5]:
            print(f"  {host_text}:{port}/tcp: {message}")

    records: list[ScanRecord] = []
    total_open_ports = 0
    print()
    for host_text in host_texts:
        entries = sorted(open_by_host[host_text])
        if not entries:
            print(f"Không tìm thấy cổng mở trên {host_text}.")
            continue
        print(f"Cổng mở trên {host_text}:")
        for port, banner in entries:
            print(format_port_line(port, banner))
        total_open_ports += len(entries)
        banners = {port: banner for port, banner in entries if banner}
        records.extend(
            build_records(
                host_text,
                [port for port, _ in entries],
                banners,
                scanned_at,
            )
        )

    if len(host_texts) == 1:
        print(f"\nHoàn tất: {total_open_ports} cổng mở trong {elapsed:.2f} giây.")
    else:
        print(
            f"\nTổng cộng: {len(host_texts)} host, {total_open_ports} cổng mở "
            f"trong {elapsed:.2f} giây."
        )

    report_status = save_report_if_requested(args, hosts, ports, records, elapsed)

    if errors and not total_open_ports:
        print("Kiểm tra kết nối mạng hoặc thử tăng --timeout.")
        return 1
    return 0 if report_status == 0 else 1


def run_scan(
    hosts: list[ipaddress.IPv4Address],
    args: argparse.Namespace,
) -> int:
    """Giai đoạn 2: kiểm tra giới hạn bằng số host THẬT rồi quét cổng."""
    if not enforce_stage_limits(
        STAGE_SCAN,
        len(hosts),
        len(args.ports),
        args.timeout,
        args.workers,
        args.confirm_large_scan,
    ):
        return 1

    return scan_hosts(hosts, args)


def resolve_scan_targets(
    args: argparse.Namespace,
) -> list[ipaddress.IPv4Address] | None:
    """Xác định danh sách host của `scan`; None khi tham số không hợp lệ."""
    provided = [
        args.target is not None,
        args.hosts is not None,
        args.hosts_file is not None,
    ]
    if sum(provided) == 0:
        print(
            "Lỗi: cần một mục tiêu: một IP đơn, hoặc --hosts <ip1,ip2,...>, "
            "hoặc --hosts-file <file JSON do 'main.py discover' tạo ra>."
        )
        return None
    if sum(provided) > 1:
        print(
            "Lỗi: chỉ được dùng một nguồn host: mục tiêu IP, --hosts "
            "hoặc --hosts-file."
        )
        return None

    if args.target is not None:
        text = args.target.strip()
        if "/" in text:
            print(f"Lỗi: {SCAN_CIDR_HINT}")
            return None
        try:
            ip = parse_target(text)
        except argparse.ArgumentTypeError as exc:
            print(f"Lỗi: {exc}")
            return None
        if isinstance(ip, ipaddress.IPv4Network):
            print(f"Lỗi: {SCAN_CIDR_HINT}")
            return None
        if not is_internal(ip) and not confirm_external_target(
            ip, assume_yes=args.yes
        ):
            print("Đã hủy quét.")
            return None
        return [ip]

    if args.hosts is not None:
        try:
            return parse_host_list(args.hosts)
        except ValueError as exc:
            print(f"Lỗi: --hosts: {exc}")
            return None

    try:
        return load_hosts_file(args.hosts_file)
    except ValueError as exc:
        print(f"Lỗi: {exc}")
        return None


def add_discover_parser(subparsers: argparse._SubParsersAction) -> None:
    """Thêm subcommand `discover`: chỉ dò host sống trong CIDR."""
    parser = subparsers.add_parser(
        "discover",
        help="dò host sống trong một dải CIDR (không quét cổng)",
        description=(
            "Giai đoạn 1: dò host sống trong một dải CIDR rồi in danh sách thu "
            "được. Không quét cổng. Dùng danh sách đó cho 'scan' ở bước sau."
        ),
    )
    parser.add_argument(
        "cidr",
        type=parse_target,
        metavar="CIDR",
        help=f"dải CIDR từ /{CIDR_MIN_PREFIX} đến /32, ví dụ 192.168.1.0/24",
    )
    parser.add_argument(
        "--discovery-ports",
        default="22,80,135,443,445",
        type=parse_ports,
        metavar="PORTS",
        help="cổng dùng để dò host sống (mặc định: 22,80,135,443,445)",
    )
    parser.add_argument(
        "--discovery-timeout",
        default=0.3,
        type=positive_float,
        metavar="GIÂY",
        help="thời gian chờ mỗi lần thử khi dò host sống (mặc định: 0.3)",
    )
    parser.add_argument(
        "--concurrency",
        default=DEFAULT_CONCURRENCY,
        type=concurrency_value,
        metavar="N",
        help=(
            f"số luồng dò song song, từ 1 đến {format_attempts(MAX_CONCURRENCY)} "
            f"(mặc định: {DEFAULT_CONCURRENCY}; trên "
            f"{format_attempts(CONCURRENCY_WARN)} luồng sẽ cảnh báo)"
        ),
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help=(
            "ghi danh sách host sống ra JSON để dùng lại với "
            "'scan --hosts-file'; nếu chỉ ghi tên file thì đặt trong reports/"
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="ghi đè file kết quả đã tồn tại mà không hỏi",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="tự xác nhận dò mục tiêu ngoài dải nội bộ",
    )
    parser.add_argument(
        "--confirm-large-scan",
        action="store_true",
        help=(
            "tự xác nhận khi giai đoạn dò vượt mốc "
            f"{format_attempts(WARN_ATTEMPTS)} lượt"
        ),
    )


def add_scan_arguments(
    parser: argparse.ArgumentParser,
    target_default: str | None = None,
) -> None:
    """Thêm tham số của giai đoạn quét cổng (dùng chung cho `scan` và lệnh cũ)."""
    parser.add_argument(
        "target",
        nargs="?",
        default=target_default,
        metavar="IP",
        help="một địa chỉ IPv4 đơn (không nhận CIDR; hãy chạy 'discover' trước)",
    )
    parser.add_argument(
        "--hosts",
        metavar="IP1,IP2,...",
        help=(
            "danh sách host phân cách bằng dấu phẩy, "
            "ví dụ 192.168.1.5,192.168.1.9"
        ),
    )
    parser.add_argument(
        "--hosts-file",
        metavar="FILE",
        help="file JSON do 'main.py discover --output' tạo ra",
    )
    parser.add_argument(
        "--ports",
        default="1-1024",
        type=parse_ports,
        metavar="PORTS",
        help=(
            "dải cổng, ví dụ 1-1024 hoặc 22,80,443; tối đa 1-65535 "
            "(mặc định: 1-1024)"
        ),
    )
    parser.add_argument(
        "--timeout",
        default=1.0,
        type=positive_float,
        metavar="GIÂY",
        help="thời gian chờ tối đa cho mỗi kết nối (mặc định: 1.0)",
    )
    parser.add_argument(
        "--banner-timeout",
        default=0.5,
        type=positive_float,
        metavar="GIÂY",
        help="thời gian chờ đọc banner cho mỗi cổng mở (mặc định: 0.5)",
    )
    parser.add_argument(
        "--workers",
        default=DEFAULT_CONCURRENCY,
        type=concurrency_value,
        metavar="N",
        help=(
            f"số luồng quét song song, từ 1 đến {format_attempts(MAX_CONCURRENCY)} "
            f"(mặc định: {DEFAULT_CONCURRENCY}; trên "
            f"{format_attempts(CONCURRENCY_WARN)} luồng sẽ cảnh báo)"
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="ghi đè file báo cáo đã tồn tại mà không hỏi",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="tự xác nhận quét mục tiêu ngoài dải nội bộ",
    )
    parser.add_argument(
        "--confirm-large-scan",
        action="store_true",
        help=(
            "tự xác nhận khi giai đoạn quét vượt mốc "
            f"{format_attempts(WARN_ATTEMPTS)} lượt"
        ),
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="ghi báo cáo ra file; nếu chỉ ghi tên file thì đặt trong reports/",
    )
    parser.add_argument(
        "--format",
        dest="report_format",
        choices=("json", "csv"),
        default="json",
        help="định dạng báo cáo khi có --output (mặc định: json)",
    )


def add_scan_parser(subparsers: argparse._SubParsersAction) -> None:
    """Thêm subcommand `scan`: quét cổng trên host đã biết, không dò CIDR."""
    parser = subparsers.add_parser(
        "scan",
        help="quét cổng trên một IP đơn hoặc danh sách host đã biết",
        description=(
            "Giai đoạn 2: quét cổng trên một IP đơn, trên --hosts, hoặc trên "
            "danh sách host do 'discover' tạo ra. Không tự dò host sống."
        ),
    )
    add_scan_arguments(parser)


def build_parser() -> argparse.ArgumentParser:
    """Tạo bộ phân tích tham số có hai subcommand discover và scan."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "Quét cổng TCP bằng TCP connect. Hai giai đoạn tách rời: 'discover' "
            "dò host sống trong CIDR, 'scan' quét cổng trên danh sách host đã "
            "biết hoặc một IP đơn."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", metavar="{discover,scan}")
    subparsers.required = True
    add_discover_parser(subparsers)
    add_scan_parser(subparsers)
    return parser


def build_legacy_parser() -> argparse.ArgumentParser:
    """Bộ phân tích kiểu cũ: 'main.py <IP> --ports ...' tương đương 'scan'."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "Cách dùng cũ, tương đương 'main.py scan': quét cổng trên một IP "
            "đơn. Muốn quét theo CIDR, hãy chạy 'main.py discover <CIDR>' trước "
            "rồi dùng --hosts-file hoặc --hosts."
        ),
    )
    # Không có subcommand thì mục tiêu mặc định vẫn là 127.0.0.1 như trước.
    add_scan_arguments(parser, target_default="127.0.0.1")
    return parser


def handle_discover(args: argparse.Namespace) -> int:
    """Xử lý subcommand discover."""
    cidr = args.cidr
    if not isinstance(cidr, ipaddress.IPv4Network):
        print(
            f"Lỗi: discover cần một dải CIDR từ /{CIDR_MIN_PREFIX} đến /32, "
            f"không nhận một IP đơn (đã nhận {cidr})."
        )
        return 1
    if not is_internal(cidr) and not confirm_external_target(
        cidr, assume_yes=args.yes
    ):
        print("Đã hủy dò host.")
        return 1
    return run_discover(args)


def handle_scan(args: argparse.Namespace) -> int:
    """Xử lý subcommand scan (và cả cách gọi cũ không có subcommand)."""
    hosts = resolve_scan_targets(args)
    if hosts is None:
        return 1
    return run_scan(hosts, args)


def main() -> int:
    """Chạy chương trình và trả về mã thoát."""
    configure_output_encoding()
    argv = sys.argv[1:]
    first = argv[0] if argv else None

    if first in SUBCOMMANDS:
        args = build_parser().parse_args(argv)
        if args.command == "discover":
            return handle_discover(args)
        return handle_scan(args)

    if first in {"-h", "--help"}:
        build_parser().print_help()
        return 0

    # Tương thích ngược: không có subcommand là cách gọi cũ cho một IP đơn
    # (chạy không tham số vẫn quét 127.0.0.1 như trước).
    return handle_scan(build_legacy_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())