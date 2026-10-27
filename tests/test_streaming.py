"""Kiểm thử quét một lượt kiểu streaming và các giới hạn tổng.

Không có lô cổng: mỗi kết quả phải được trả về ngay khi cổng đó quét xong, và
danh sách mục tiêu có thể là generator để không dựng sẵn hàng triệu cặp.

Mọi bài kiểm thử đều thay `scanner._probe_target` bằng hàm giả nên không mở
kết nối mạng nào.
"""

from __future__ import annotations

import ipaddress
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

# Cho phép chạy kiểm thử từ bất kỳ thư mục nào.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scanner  # noqa: E402
from main import (  # noqa: E402
    CONCURRENCY_WARN,
    HARD_ATTEMPTS,
    STAGE_SCAN,
    WARN_ATTEMPTS,
    parse_target,
    stage_limit_message,
)
from report import ScanRecord  # noqa: E402
from web_server import (  # noqa: E402
    MAX_CONCURRENCY,
    MAX_PORTS,
    count_target_hosts,
    sort_records,
)


def make_record(host: str, port: int) -> ScanRecord:
    return ScanRecord(
        host=host,
        port=port,
        protocol="tcp",
        service="unknown",
        banner=None,
        scanned_at="2026-10-26T00:00:00+07:00",
    )


class ConstantsTest(unittest.TestCase):
    """Các hằng số giới hạn nằm ở một chỗ và đúng giá trị đã chốt."""

    def test_max_ports(self) -> None:
        self.assertEqual(MAX_PORTS, 65535)

    def test_max_concurrency(self) -> None:
        self.assertEqual(MAX_CONCURRENCY, 10000)

    def test_concurrency_warning_threshold(self) -> None:
        self.assertEqual(CONCURRENCY_WARN, 2000)

    def test_batching_is_gone(self) -> None:
        self.assertFalse(hasattr(scanner, "scan_ports"))
        self.assertFalse(hasattr(scanner, "grab_banners"))
        import web_server

        self.assertFalse(hasattr(web_server, "chunk_ports"))
        self.assertFalse(hasattr(web_server, "BATCH_SIZE"))


class CountTargetHostsTest(unittest.TestCase):
    """Số host tối đa của mục tiêu, dùng để kiểm tra giới hạn tổng."""

    def test_single_address(self) -> None:
        self.assertEqual(count_target_hosts(ipaddress.ip_address("127.0.0.1")), 1)

    def test_slash_30(self) -> None:
        self.assertEqual(count_target_hosts(ipaddress.ip_network("127.0.0.0/30")), 2)

    def test_slash_24(self) -> None:
        self.assertEqual(count_target_hosts(ipaddress.ip_network("192.168.1.0/24")), 254)

    def test_slash_31_and_32(self) -> None:
        self.assertEqual(count_target_hosts(ipaddress.ip_network("10.0.0.0/31")), 2)
        self.assertEqual(count_target_hosts(ipaddress.ip_network("10.0.0.1/32")), 1)


class AttemptLimitTest(unittest.TestCase):
    """Hai mốc giới hạn được áp dụng riêng cho từng giai đoạn."""

    def test_one_host_full_range_is_below_warning(self) -> None:
        # IP đơn chỉ có giai đoạn quét cổng, nên chỉ tính số cổng.
        self.assertLess(1 * MAX_PORTS, WARN_ATTEMPTS)

    def test_slash_24_with_1024_ports_is_below_warning(self) -> None:
        self.assertLess(254 * 1024, WARN_ATTEMPTS)

    def test_slash_24_with_2048_ports_needs_confirmation(self) -> None:
        attempts = 254 * 2048
        self.assertGreater(attempts, WARN_ATTEMPTS)
        self.assertLessEqual(attempts, HARD_ATTEMPTS)

    def test_slash_24_with_full_range_exceeds_hard_cap(self) -> None:
        self.assertGreater(254 * MAX_PORTS, HARD_ATTEMPTS)

    def test_slash_18_with_full_range_exceeds_hard_cap(self) -> None:
        self.assertGreater(16382 * MAX_PORTS, HARD_ATTEMPTS)

    def test_discovery_stage_is_counted_separately(self) -> None:
        # 16382 × 64 cổng dò = 1.048.448: vượt cảnh báo nhưng chưa tới trần.
        discovery_attempts = 16382 * 64
        self.assertGreater(discovery_attempts, WARN_ATTEMPTS)
        self.assertLessEqual(discovery_attempts, HARD_ATTEMPTS)

    def test_warning_below_hard_cap(self) -> None:
        self.assertLess(WARN_ATTEMPTS, HARD_ATTEMPTS)

    def test_message_mentions_limit_and_how_to_reduce(self) -> None:
        message = stage_limit_message(STAGE_SCAN, 16382, MAX_PORTS)
        self.assertIn("5.000.000", message)
        self.assertIn("giai đoạn quét cổng", message)
        self.assertIn("16382 host", message)
        self.assertIn("giảm số cổng", message)
        self.assertIn("bớt host", message)

    def test_slash_18_is_accepted_and_slash_17_is_not(self) -> None:
        self.assertEqual(str(parse_target("10.0.0.0/18")), "10.0.0.0/18")
        with self.assertRaises(Exception):
            parse_target("10.0.0.0/17")


class SortRecordsTest(unittest.TestCase):
    """Kết quả sắp theo IP (so sánh số) rồi theo cổng."""

    def test_sorted_by_ip_number_not_string(self) -> None:
        records = [
            make_record("192.168.1.10", 80),
            make_record("192.168.1.9", 445),
            make_record("192.168.1.9", 80),
            make_record("192.168.1.100", 22),
        ]
        ordered = [(r.host, r.port) for r in sort_records(records)]
        self.assertEqual(
            ordered,
            [
                ("192.168.1.9", 80),
                ("192.168.1.9", 445),
                ("192.168.1.10", 80),
                ("192.168.1.100", 22),
            ],
        )

    def test_different_octets(self) -> None:
        records = [
            make_record("10.0.0.2", 80),
            make_record("10.0.0.1", 443),
            make_record("9.255.255.255", 80),
        ]
        ordered = [(r.host, r.port) for r in sort_records(records)]
        self.assertEqual(
            ordered,
            [("9.255.255.255", 80), ("10.0.0.1", 443), ("10.0.0.2", 80)],
        )

    def test_sorted_by_port_within_host(self) -> None:
        records = [
            make_record("127.0.0.1", 445),
            make_record("127.0.0.1", 135),
            make_record("127.0.0.1", 4096),
        ]
        self.assertEqual(
            [r.port for r in sort_records(records)], [135, 445, 4096]
        )

    def test_does_not_modify_input_list(self) -> None:
        records = [make_record("10.0.0.2", 80), make_record("10.0.0.1", 80)]
        sort_records(records)
        self.assertEqual(records[0].host, "10.0.0.2")


class ScanTargetsTest(unittest.TestCase):
    """`scan_targets` trả kết quả ngay từng cổng, không chờ lô."""

    def run_scan(self, targets, fake, **kwargs):
        with mock.patch.object(scanner, "_probe_target", fake):
            return scanner.scan_targets(targets, **kwargs)

    def test_open_ports_are_returned_and_sorted(self) -> None:
        open_ports = {("127.0.0.1", 135), ("127.0.0.1", 445)}

        def fake(host, port, timeout, banner_timeout):
            return (host, port) in open_ports, None

        found, errors = self.run_scan(
            list(open_ports), fake, total=2, workers=4
        )

        self.assertEqual(found, sorted(open_ports))
        self.assertEqual(errors, [])

    def test_result_is_streamed_before_all_targets_finish(self) -> None:
        first_result_at: list[int] = []
        done_counter = {"done": 0}

        def on_result(host, port, banner):
            first_result_at.append(done_counter["done"])

        def on_progress(done, total):
            done_counter["done"] = done

        def fake(host, port, timeout, banner_timeout):
            if port == 1:
                return True, "banner"
            time.sleep(0.02)
            return False, None

        self.run_scan(
            [("127.0.0.1", port) for port in range(1, 21)],
            fake,
            total=20,
            workers=2,
            on_result=on_result,
            on_progress=on_progress,
        )

        self.assertEqual(len(first_result_at), 1)
        # Kết quả đầu tiên phải tới khi chưa quét xong toàn bộ danh sách.
        self.assertLess(first_result_at[0], 20)

    def test_generator_targets_are_consumed_lazily(self) -> None:
        pulled: list[int] = []

        def targets():
            for port in range(1, 1000):
                pulled.append(port)
                yield ("127.0.0.1", port)

        def fake(host, port, timeout, banner_timeout):
            return False, None

        found, errors = self.run_scan(
            targets(),
            fake,
            total=5,
            workers=2,
            should_cancel=lambda: True,
        )

        self.assertEqual((found, errors), ([], []))
        self.assertEqual(pulled, [], "hủy trước khi quét thì không được nạp task")

    def test_cancel_keeps_finished_results(self) -> None:
        scanned: list[int] = []
        lock = threading.Lock()

        def fake(host, port, timeout, banner_timeout):
            with lock:
                scanned.append(port)
            if port == 1:
                return True, None
            time.sleep(0.05)
            return False, None

        def on_result(host, port, banner):
            pass

        cancel = {"value": False}

        def should_cancel():
            return cancel["value"]

        def on_progress(done, total):
            if done >= 1:
                cancel["value"] = True

        found, _ = self.run_scan(
            [("127.0.0.1", port) for port in range(1, 201)],
            fake,
            total=200,
            workers=4,
            on_result=on_result,
            on_progress=on_progress,
            should_cancel=should_cancel,
        )

        self.assertTrue(found)
        self.assertLess(len(scanned), 200, "hủy phải dừng việc nạp task mới")

    def test_network_errors_are_collected(self) -> None:
        def fake(host, port, timeout, banner_timeout):
            if port == 7:
                raise OSError("mạng không phản hồi")
            return port == 22, None

        found, errors = self.run_scan(
            [("127.0.0.1", 7), ("127.0.0.1", 22)],
            fake,
            total=2,
            workers=2,
        )

        self.assertEqual(found, [("127.0.0.1", 22)])
        self.assertEqual(errors, [("127.0.0.1", 7, "mạng không phản hồi")])

    def test_progress_reaches_total(self) -> None:
        seen: list[tuple[int, int]] = []

        def fake(host, port, timeout, banner_timeout):
            return False, None

        self.run_scan(
            [("127.0.0.1", port) for port in range(1, 6)],
            fake,
            total=5,
            workers=3,
            on_progress=lambda done, total: seen.append((done, total)),
        )

        self.assertEqual(seen[-1], (5, 5))

    def test_banner_is_passed_to_on_result(self) -> None:
        banners: list[str | None] = []

        def fake(host, port, timeout, banner_timeout):
            return True, "SSH-2.0-OpenSSH"

        self.run_scan(
            [("127.0.0.1", 22)],
            fake,
            total=1,
            workers=1,
            on_result=lambda host, port, banner: banners.append(banner),
        )

        self.assertEqual(banners, ["SSH-2.0-OpenSSH"])


if __name__ == "__main__":
    unittest.main()
