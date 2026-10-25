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
