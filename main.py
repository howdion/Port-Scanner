"""Điểm vào chương trình quét cổng TCP."""

from __future__ import annotations

import argparse
import ipaddress
import math
import sys
import time
from datetime import datetime
from pathlib import Path

from report import ScanRecord, write_report
from scanner import discover_hosts, grab_banners, scan_ports
from services import get_service_name


# Các dải IP nội bộ được phép quét theo quy định an toàn của dự án.
_INTERNAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)


def configure_output_encoding() -> None:
    """Ép stdout/stderr dùng UTF-8 để in tiếng Việt trên Windows."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")


def parse_target(value: str) -> ipaddress.IPv4Address | ipaddress.IPv4Network:
    """Kiểm tra tham số mục tiêu là IPv4 hoặc CIDR IPv4 tối đa /24."""
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != 4:
                raise argparse.ArgumentTypeError("hiện chỉ hỗ trợ địa chỉ IPv4")
            if network.prefixlen < 24:
                raise argparse.ArgumentTypeError(
                    "chỉ hỗ trợ dải CIDR tối đa /24; dải lớn hơn bị từ chối"
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


def positive_int(value: str) -> int:
    """Kiểm tra số luồng là số nguyên lớn hơn 0."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("số luồng phải là số nguyên") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("số luồng phải lớn hơn 0")
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
) -> bool:
    """Cảnh báo và xin xác nhận trước khi quét mục tiêu ngoài dải nội bộ."""
    print(f"CẢNH BÁO: {target} không nằm trong dải IP nội bộ.")
    print("Công cụ này chỉ dùng để quét máy của bạn, mạng nhà bạn hoặc máy ảo lab.")
    print("Chỉ tiếp tục nếu bạn có quyền quét mục tiêu này.")
    try:
        answer = input("Tiếp tục quét? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in {"y", "yes"}


def format_port_line(port: int, banner: str | None) -> str:
    """Định dạng một dòng kết quả cổng kèm tên dịch vụ và banner."""
    line = f"  {port}/tcp  {get_service_name(port)}"
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


def save_report_if_requested(
    args: argparse.Namespace,
    target: ipaddress.IPv4Address | ipaddress.IPv4Network,
    ports: list[int],
    records: list[ScanRecord],
    duration: float,
) -> int:
    """Ghi báo cáo nếu có --output; trả về 0 nếu thành công hoặc không cần ghi."""
    if not args.output:
        return 0

    try:
        path = resolve_output_path(args.output)
    except ValueError as exc:
        print(f"Lỗi: {exc}")
        return 1

    if path.exists():
        if path.is_dir():
            print(f"Lỗi: đường dẫn báo cáo là thư mục: {path}")
            return 1
        print(f"File báo cáo đã tồn tại: {path}")
        try:
            answer = input("Ghi đè? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            answer = ""
        if answer not in {"y", "yes"}:
            print("Không ghi đè; báo cáo không được tạo.")
            return 1

    metadata = {
        "target": str(target),
        "port_range": format_port_spec(ports),
        "total_open_ports": len(records),
        "scan_duration_seconds": round(duration, 3),
    }

    try:
        write_report(path, args.report_format, records, metadata)
    except (OSError, ValueError) as exc:
        print(f"Lỗi: không thể ghi báo cáo {path}: {exc}")
        return 1

    print(f"Đã ghi báo cáo: {path}")
    return 0


def scan_network(
    network: ipaddress.IPv4Network,
    args: argparse.Namespace,
) -> int:
    """Dò host sống rồi quét cổng từng host trong dải CIDR."""
    hosts = [str(host) for host in network.hosts()]
    print(
        f"Đang kiểm tra host sống trong {network} "
        f"({len(hosts)} host, timeout {args.discovery_timeout}s)..."
    )

    def report_progress(done: int, total: int, host: str, is_alive: bool) -> None:
        status = "sống" if is_alive else "không phản hồi"
        print(f"[{done}/{total}] {host}: {status}")

    records: list[ScanRecord] = []
    report_started = time.perf_counter()
    try:
        alive_hosts = discover_hosts(
            hosts,
            timeout=args.discovery_timeout,
            workers=args.workers,
            on_progress=report_progress,
        )
    except KeyboardInterrupt:
        print("\nĐã hủy bởi người dùng.")
        return 130
    elapsed = time.perf_counter() - report_started

    print(
        f"\nTìm thấy {len(alive_hosts)}/{len(hosts)} host sống "
        f"trong {elapsed:.2f} giây."
    )
    if not alive_hosts:
        print("Không có host nào phản hồi; bỏ qua quét cổng.")
        total_elapsed = time.perf_counter() - report_started
        report_status = save_report_if_requested(
            args, network, args.ports, records, total_elapsed
        )
        return 1 if report_status != 0 else 0

    total_open_ports = 0
    for index, host in enumerate(alive_hosts, start=1):
        print(
            f"\n[{index}/{len(alive_hosts)}] Đang quét {host} "
            f"({len(args.ports)} cổng)..."
        )
        host_started = time.perf_counter()
        try:
            open_ports, errors = scan_ports(
                host,
                args.ports,
                timeout=args.timeout,
                workers=args.workers,
            )
            banners = grab_banners(
                host,
                open_ports,
                timeout=args.banner_timeout,
                workers=args.workers,
            )
        except KeyboardInterrupt:
            print("\nĐã hủy bởi người dùng.")
            return 130
        host_elapsed = time.perf_counter() - host_started
        scanned_at = current_timestamp()
        records.extend(build_records(host, open_ports, banners, scanned_at))

        if errors:
            print(f"Cảnh báo: {len(errors)} cổng gặp lỗi mạng, ví dụ:")
            for port, message in errors[:5]:
                print(f"  {port}/tcp: {message}")

        if open_ports:
            print(f"Cổng mở trên {host}:")
            for port in open_ports:
                print(format_port_line(port, banners.get(port)))
            total_open_ports += len(open_ports)
        else:
            print(f"Không tìm thấy cổng mở trên {host}.")

        print(
            f"Hoàn tất host {host}: {len(open_ports)} cổng mở "
            f"trong {host_elapsed:.2f} giây."
        )

    print(
        f"\nTổng cộng: {len(alive_hosts)} host sống, "
        f"{total_open_ports} cổng mở."
    )

    total_elapsed = time.perf_counter() - report_started
    report_status = save_report_if_requested(
        args, network, args.ports, records, total_elapsed
    )
    return 1 if report_status != 0 else 0


def build_parser() -> argparse.ArgumentParser:
    """Tạo bộ phân tích tham số dòng lệnh."""
    parser = argparse.ArgumentParser(
        description="Quét cổng TCP bằng TCP connect (IPv4 hoặc CIDR tối đa /24).",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=ipaddress.ip_address("127.0.0.1"),
        type=parse_target,
        metavar="IP/CIDR",
        help="địa chỉ IPv4 hoặc dải CIDR tối đa /24 (mặc định: 127.0.0.1)",
    )
    parser.add_argument(
        "--ports",
        default="1-1024",
        type=parse_ports,
        metavar="PORTS",
        help="dải cổng, ví dụ 1-1024 hoặc 22,80,443 (mặc định: 1-1024)",
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
        "--discovery-timeout",
        default=0.3,
        type=positive_float,
        metavar="GIÂY",
        help="thời gian chờ dò host sống trong CIDR (mặc định: 0.3)",
    )
    parser.add_argument(
        "--workers",
        default=100,
        type=positive_int,
        metavar="N",
        help="số luồng quét song song (mặc định: 100)",
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
    return parser


def main() -> int:
    """Chạy chương trình và trả về mã thoát."""
    configure_output_encoding()
    args = build_parser().parse_args()
    target: ipaddress.IPv4Address | ipaddress.IPv4Network = args.target

    if not is_internal(target) and not confirm_external_target(target):
        print("Đã hủy quét.")
        return 1

    if isinstance(target, ipaddress.IPv4Network):
        return scan_network(target, args)

    print(
        f"Đang quét {target} với {len(args.ports)} cổng "
        f"(timeout {args.timeout}s, banner {args.banner_timeout}s, "
        f"{args.workers} luồng)..."
    )
    started = time.perf_counter()
    try:
        open_ports, errors = scan_ports(
            str(target),
            args.ports,
            timeout=args.timeout,
            workers=args.workers,
        )
        banners = grab_banners(
            str(target),
            open_ports,
            timeout=args.banner_timeout,
            workers=args.workers,
        )
    except KeyboardInterrupt:
        print("\nĐã hủy bởi người dùng.")
        return 130
    elapsed = time.perf_counter() - started
    scanned_at = current_timestamp()
    records = build_records(str(target), open_ports, banners, scanned_at)

    if errors:
        print(f"\nCảnh báo: {len(errors)} cổng gặp lỗi mạng, ví dụ:")
        for port, message in errors[:5]:
            print(f"  {port}/tcp: {message}")

    print()
    if open_ports:
        print(f"Cổng mở trên {target}:")
        for port in open_ports:
            print(format_port_line(port, banners.get(port)))
    else:
        print(f"Không tìm thấy cổng mở trên {target}.")

    print(f"\nHoàn tất: {len(open_ports)} cổng mở trong {elapsed:.2f} giây.")

    report_status = save_report_if_requested(
        args, target, args.ports, records, elapsed
    )

    if errors and not open_ports:
        print("Kiểm tra kết nối mạng hoặc thử tăng --timeout.")
        return 1
    return 0 if report_status == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
