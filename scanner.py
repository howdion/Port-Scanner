"""Logic quét cổng TCP bằng kết nối TCP connect."""

from __future__ import annotations

import errno
import socket
from collections.abc import Callable, Iterable
from concurrent.futures import (
    FIRST_COMPLETED,
    Future,
    ThreadPoolExecutor,
    as_completed,
    wait,
)


# Các mã lỗi cho biết cổng đóng, bị lọc hoặc hết thời gian chờ.
# connect_ex() trả về mã lỗi thay vì ném ngoại lệ với các trường hợp này.
# WSAEACCES (10013) trên Windows thường do firewall chặn kết nối.
_CLOSED_PORT_ERRORS = {
    errno.ECONNREFUSED,
    errno.ECONNRESET,
    errno.ECONNABORTED,
    errno.ETIMEDOUT,
    errno.EAGAIN,
    errno.EWOULDBLOCK,
    errno.EINPROGRESS,
    getattr(errno, "WSAEACCES", -1),
}


# Các cổng thường dùng giao thức HTTP: gửi thêm yêu cầu HEAD để lấy banner.
_HTTP_PORTS = {80, 3000, 5000, 5357, 8000, 8008, 8080, 8081, 8888}

# Các cổng TLS không trả banner dạng plaintext; cần handshake TLS riêng.
_TLS_PORTS = {443, 465, 636, 990, 993, 995, 8443}

# Cổng dùng để dò nhanh host còn sống trước khi quét toàn bộ dải cổng.
DISCOVERY_PORTS: tuple[int, ...] = (22, 80, 135, 443, 445)


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Quét một cổng TCP, trả về True nếu cổng đang mở.

    Args:
        host: Địa chỉ IPv4 của mục tiêu.
        port: Cổng cần kiểm tra (1-65535).
        timeout: Thời gian chờ tối đa cho một lần kết nối (giây).

    Raises:
        OSError: Khi gặp lỗi mạng không phải cổng đóng hoặc bị lọc.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            # connect_ex() thực hiện TCP handshake và trả về mã lỗi thay vì
            # ném ngoại lệ. Mã 0 nghĩa là handshake thành công
            # (SYN -> SYN/ACK -> ACK), tức là có tiến trình đang lắng nghe
            # trên cổng này.
            result = sock.connect_ex((host, port))
        except socket.timeout:
            # Hết thời gian chờ: coi như cổng đóng hoặc bị lọc.
            return False

    if result == 0:
        return True
    if result in _CLOSED_PORT_ERRORS:
        return False

    raise OSError(result, f"Không thể kết nối tới {host}:{port} (mã lỗi {result})")


def _probe_target(
    host: str,
    port: int,
    timeout: float,
    banner_timeout: float,
) -> tuple[bool, str | None]:
    """Quét một cổng và đọc banner ngay nếu cổng mở.

    Trả về ``(mở, banner)``. Banner chỉ được đọc cho cổng đã mở nên không làm
    chậm các cổng đóng. Lỗi mạng được để ném ra cho ``scan_targets`` ghi nhận.
    """
    if not scan_port(host, port, timeout):
        return False, None
    return True, grab_banner(host, port, banner_timeout)


def scan_targets(
    targets: Iterable[tuple[str, int]],
    *,
    total: int,
    workers: int = 100,
    timeout: float = 1.0,
    banner_timeout: float = 0.5,
    on_result: Callable[[str, int, str | None], None] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> tuple[list[tuple[str, int]], list[tuple[str, int, str]]]:
    """Quét một lượt toàn bộ danh sách ``(host, cổng)``, trả kết quả ngay.

    Không chia lô: task được nạp dần vào một cửa sổ giới hạn (khoảng hai lần số
    luồng) để không tạo hàng triệu Future cùng lúc, nhưng mỗi cổng quét xong là
    được trả về ngay qua ``on_result``, không chờ nhóm nào hoàn tất.

    Args:
        targets: Iterable các cặp ``(host, cổng)``; có thể là generator.
        total: Tổng số lượt quét, dùng cho tiến độ ``done/total``.
        workers: Số luồng quét song song.
        timeout: Thời gian chờ tối đa cho mỗi lần kết nối (giây).
        banner_timeout: Thời gian chờ đọc banner của một cổng mở (giây).
        on_result: Callback nhận ``(host, cổng, banner)`` ngay khi tìm thấy cổng
            mở; ``banner`` là ``None`` nếu không đọc được.
        on_progress: Callback nhận ``(đã xong, tổng)`` sau mỗi cổng.
        should_cancel: Callback trả về True để dừng sớm; kết quả đã có vẫn được
            giữ nguyên và trả về.

    Returns:
        Một tuple gồm danh sách ``(host, cổng)`` đang mở và danh sách lỗi mạng
        dạng ``(host, cổng, thông báo)``.
    """
    open_ports: list[tuple[str, int]] = []
    errors: list[tuple[str, int, str]] = []
    done = 0

    worker_count = max(1, min(workers, max(1, total)))
    # Cửa sổ task chờ: đủ lớn để luôn có việc cho mọi luồng, nhưng có trần để
    # không dựng hàng triệu Future khi danh sách cổng rất dài.
    window = max(worker_count * 2, 64)

    iterator = iter(targets)
    pending: dict[Future[tuple[bool, str | None]], tuple[str, int]] = {}
    exhausted = False

    executor = ThreadPoolExecutor(max_workers=worker_count)
    try:
        while True:
            # Người dùng hủy: thôi nạp task mới, vẫn thu nốt kết quả đã xong.
            cancelled = should_cancel is not None and should_cancel()
            while not cancelled and not exhausted and len(pending) < window:
                try:
                    host, port = next(iterator)
                except StopIteration:
                    exhausted = True
                    break
                future = executor.submit(
                    _probe_target, host, port, timeout, banner_timeout
                )
                pending[future] = (host, port)

            if not pending:
                break

            finished, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in finished:
                host, port = pending.pop(future)
                try:
                    is_open, banner = future.result()
                except OSError as exc:
                    errors.append((host, port, str(exc)))
                else:
                    if is_open:
                        open_ports.append((host, port))
                        if on_result is not None:
                            on_result(host, port, banner)
                done += 1
                if on_progress is not None:
                    on_progress(done, total)

            if should_cancel is not None and should_cancel():
                break
    finally:
        # Các task đang chạy tự kết thúc trong khoảng timeout nên không treo lâu.
        executor.shutdown(wait=True, cancel_futures=True)

    open_ports.sort()
    return open_ports, errors


def discover_host(
    host: str,
    ports: tuple[int, ...] = DISCOVERY_PORTS,
    timeout: float = 0.3,
) -> bool:
    """Kiểm tra nhanh một host còn sống bằng TCP connect tới vài cổng phổ biến.

    Quét toàn bộ dải cổng trên mọi host trong một dải CIDR rất tốn thời gian.
    Thử trước vài cổng hay mở giúp loại nhanh các host không phản hồi; chỉ host
    sống mới được quét kỹ.
    """
    for port in ports:
        try:
            if scan_port(host, port, timeout):
                return True
        except OSError:
            # Lỗi mạng khi dò host: coi như không phản hồi và thử cổng tiếp theo.
            continue
    return False


def discover_hosts(
    hosts: list[str],
    ports: tuple[int, ...] = DISCOVERY_PORTS,
    timeout: float = 0.3,
    workers: int = 100,
    on_progress: Callable[[int, int, str, bool], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> list[str]:
    """Dò song song các host còn sống trong danh sách.

    Args:
        hosts: Danh sách địa chỉ IPv4 cần dò.
        ports: Các cổng dùng để thử kết nối.
        timeout: Thời gian chờ tối đa cho mỗi lần thử (giây).
        workers: Số luồng dò song song.
        on_progress: Hàm callback nhận (đã xong, tổng, host, còn sống) sau mỗi host.
        should_cancel: Callback tùy chọn; trả về True để dừng dò sớm.

    Returns:
        Danh sách host sống, giữ nguyên thứ tự đầu vào.
    """
    if not hosts:
        return []

    statuses: dict[str, bool] = {}
    max_workers = max(1, min(workers, len(hosts)))
    cancelled = False

    executor = ThreadPoolExecutor(max_workers=max_workers)
    try:
        futures = {
            executor.submit(discover_host, host, ports, timeout): host
            for host in hosts
        }
        for done, future in enumerate(as_completed(futures), start=1):
            if should_cancel is not None and should_cancel():
                cancelled = True
                break
            host = futures[future]
            try:
                is_alive = future.result()
            except OSError:
                is_alive = False
            statuses[host] = is_alive
            if on_progress is not None:
                on_progress(done, len(hosts), host, is_alive)
    finally:
        executor.shutdown(wait=True, cancel_futures=cancelled)

    return [host for host in hosts if statuses.get(host)]


def _clean_banner(data: bytes, max_length: int = 120) -> str:
    """Chuẩn hóa dữ liệu thô thành một dòng banner ngắn, dễ đọc."""
    text = data.decode("utf-8", errors="replace")
    lines: list[str] = []
    for raw_line in text.splitlines():
        # Loại bỏ ký tự điều khiển và gộp khoảng trắng để banner không phá định dạng.
        line = "".join(char if char.isprintable() else " " for char in raw_line)
        line = " ".join(line.split())
        if line:
            lines.append(line)

    if not lines:
        return ""

    # Với HTTP, ưu tiên header Server vì ngắn và mô tả đúng phần mềm máy chủ.
    for line in lines:
        if line.lower().startswith("server:"):
            return line[:max_length]
    return " | ".join(lines[:2])[:max_length]


def grab_banner(host: str, port: int, timeout: float = 0.5) -> str | None:
    """Thử đọc banner ngắn từ một cổng đã mở.

    Banner là dữ liệu đầu tiên dịch vụ gửi sau khi kết nối. Với các cổng HTTP,
    chương trình gửi thêm một yêu cầu HEAD tối giản để máy chủ trả về header.

    Args:
        host: Địa chỉ IPv4 của mục tiêu.
        port: Cổng đã được xác nhận là mở.
        timeout: Thời gian chờ tối đa khi kết nối và đọc dữ liệu (giây).

    Returns:
        Banner đã rút gọn, hoặc ``None`` nếu không đọc được.
    """
    if port in _TLS_PORTS:
        # TLS cần handshake riêng; bước này chỉ đọc banner plaintext.
        return None

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in _HTTP_PORTS:
                request = (
                    "HEAD / HTTP/1.0\r\n"
                    f"Host: {host}\r\n"
                    "User-Agent: PortScanner/1.0\r\n"
                    "\r\n"
                ).encode("ascii")
                sock.sendall(request)
            data = sock.recv(1024)
    except OSError:
        # Banner chỉ là thông tin bổ sung; lỗi đọc banner không làm hỏng kết quả quét.
        return None

    if not data:
        return None
    return _clean_banner(data) or None

