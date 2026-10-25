"""Điểm vào chương trình quét cổng TCP."""

from __future__ import annotations

import argparse
import ipaddress
import math
import sys
import time

from scanner import scan_ports


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


def parse_target(value: str) -> ipaddress.IPv4Address:
    """Kiểm tra tham số mục tiêu là một địa chỉ IPv4 hợp lệ."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"địa chỉ IP không hợp lệ: {value!r}"
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


def is_internal(ip: ipaddress.IPv4Address) -> bool:
    """Kiểm tra IP có thuộc dải nội bộ được phép quét hay không."""
    return any(ip in network for network in _INTERNAL_NETWORKS)


def confirm_external_target(ip: ipaddress.IPv4Address) -> bool:
    """Cảnh báo và xin xác nhận trước khi quét IP ngoài dải nội bộ."""
    print(f"CẢNH BÁO: {ip} không nằm trong dải IP nội bộ.")
    print("Công cụ này chỉ dùng để quét máy của bạn, mạng nhà bạn hoặc máy ảo lab.")
    print("Chỉ tiếp tục nếu bạn có quyền quét mục tiêu này.")
    try:
        answer = input("Tiếp tục quét? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in {"y", "yes"}


def build_parser() -> argparse.ArgumentParser:
    """Tạo bộ phân tích tham số dòng lệnh."""
    parser = argparse.ArgumentParser(
        description="Quét cổng TCP bằng TCP connect (chỉ hỗ trợ IPv4).",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=ipaddress.ip_address("127.0.0.1"),
        type=parse_target,
        metavar="IP",
        help="địa chỉ IPv4 cần quét (mặc định: 127.0.0.1)",
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
        "--workers",
        default=100,
        type=positive_int,
        metavar="N",
        help="số luồng quét song song (mặc định: 100)",
    )
    return parser


def main() -> int:
    """Chạy chương trình và trả về mã thoát."""
    configure_output_encoding()
    args = build_parser().parse_args()
    target: ipaddress.IPv4Address = args.target

    if not is_internal(target) and not confirm_external_target(target):
        print("Đã hủy quét.")
        return 1

    print(
        f"Đang quét {target} với {len(args.ports)} cổng "
        f"(timeout {args.timeout}s, {args.workers} luồng)..."
    )
    started = time.perf_counter()
    try:
        open_ports, errors = scan_ports(
            str(target),
            args.ports,
            timeout=args.timeout,
            workers=args.workers,
        )
    except KeyboardInterrupt:
        print("\nĐã hủy bởi người dùng.")
        return 130
    elapsed = time.perf_counter() - started

    if errors:
        print(f"\nCảnh báo: {len(errors)} cổng gặp lỗi mạng, ví dụ:")
        for port, message in errors[:5]:
            print(f"  {port}/tcp: {message}")

    print()
    if open_ports:
        print(f"Cổng mở trên {target}:")
        for port in open_ports:
            print(f"  {port}/tcp")
    else:
        print(f"Không tìm thấy cổng mở trên {target}.")

    print(f"\nHoàn tất: {len(open_ports)} cổng mở trong {elapsed:.2f} giây.")

    if errors and not open_ports:
        print("Kiểm tra kết nối mạng hoặc thử tăng --timeout.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
