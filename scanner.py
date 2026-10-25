"""Logic quét cổng TCP bằng kết nối TCP connect."""

from __future__ import annotations

import errno
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


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


def scan_ports(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    workers: int = 100,
) -> tuple[list[int], list[tuple[int, str]]]:
    """Quét nhiều cổng song song bằng thread pool.

    Mỗi luồng xử lý một cổng, giới hạn số luồng để không mở quá nhiều kết nối
    cùng lúc. Các cổng đóng sẽ trả về nhanh hoặc chờ tối đa ``timeout`` giây,
    nên chương trình không bị treo.

    Returns:
        Một tuple gồm danh sách cổng mở (đã sắp xếp) và danh sách lỗi mạng
        dạng ``(cổng, thông báo)``.
    """
    open_ports: list[int] = []
    errors: list[tuple[int, str]] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except OSError as exc:
                errors.append((port, str(exc)))

    open_ports.sort()
    return open_ports, errors


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


def grab_banners(
    host: str,
    ports: list[int],
    timeout: float = 0.5,
    workers: int = 100,
) -> dict[int, str]:
    """Đọc banner song song cho danh sách cổng đã mở.

    Returns:
        Từ điển ánh xạ số cổng sang banner đọc được. Cổng không có banner sẽ
        không xuất hiện trong từ điển.
    """
    banners: dict[int, str] = {}
    if not ports:
        return banners

    max_workers = max(1, min(workers, len(ports)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(grab_banner, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            port = futures[future]
            try:
                banner = future.result()
            except OSError:
                banner = None
            if banner:
                banners[port] = banner
    return banners
