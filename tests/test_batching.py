"""Kiểm thử phần chia lô cổng và các giới hạn liên quan."""

from __future__ import annotations

import ipaddress
import sys
import unittest
from pathlib import Path

# Cho phép chạy kiểm thử từ bất kỳ thư mục nào.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from report import ScanRecord  # noqa: E402
from web_server import (  # noqa: E402
    BATCH_SIZE,
    MAX_ATTEMPTS,
    MAX_PORTS,
    attempt_limit_message,
    chunk_ports,
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

    def test_batch_size(self) -> None:
        self.assertEqual(BATCH_SIZE, 2048)

    def test_max_ports(self) -> None:
        self.assertEqual(MAX_PORTS, 65535)

    def test_max_attempts(self) -> None:
        # 256 host × 1024 cổng
        self.assertEqual(MAX_ATTEMPTS, 262144)


class ChunkPortsTest(unittest.TestCase):
    """Chia danh sách cổng thành các lô liên tiếp, tối đa BATCH_SIZE cổng."""

    def test_empty_list(self) -> None:
        self.assertEqual(chunk_ports([]), [])

    def test_single_port(self) -> None:
        self.assertEqual(chunk_ports([80]), [[80]])

    def test_shorter_than_one_batch(self) -> None:
        batches = chunk_ports(list(range(1, 1025)))
        self.assertEqual(len(batches), 1)
        self.assertEqual(batches[0][0], 1)
        self.assertEqual(batches[0][-1], 1024)

    def test_exactly_one_batch(self) -> None:
        batches = chunk_ports(list(range(1, BATCH_SIZE + 1)))
        self.assertEqual(len(batches), 1)
        self.assertEqual(len(batches[0]), BATCH_SIZE)

    def test_one_more_than_one_batch(self) -> None:
        ports = list(range(1, BATCH_SIZE + 2))
        batches = chunk_ports(ports)
        self.assertEqual(len(batches), 2)
        self.assertEqual(len(batches[0]), BATCH_SIZE)
        self.assertEqual(batches[1], [BATCH_SIZE + 1])

    def test_four_thousand_ports(self) -> None:
        batches = chunk_ports(list(range(1, 4097)))
        self.assertEqual(len(batches), 2)
        self.assertEqual(batches[0][0], 1)
        self.assertEqual(batches[0][-1], 2048)
        self.assertEqual(batches[1][0], 2049)
        self.assertEqual(batches[1][-1], 4096)

    def test_discrete_ports(self) -> None:
        # 22, 80, 443 rồi 3000-5500: tổng 2504 cổng -> 2 lô.
        ports = [22, 80, 443] + list(range(3000, 5501))
        batches = chunk_ports(ports)
        self.assertEqual(len(batches), 2)
        self.assertEqual(batches[0][:3], [22, 80, 443])
        self.assertEqual(len(batches[0]), BATCH_SIZE)
        self.assertEqual(batches[1][0], 5045)
        self.assertEqual(batches[1][-1], 5500)
        self.assertEqual(sum(len(batch) for batch in batches), 2504)

    def test_duplicates_are_removed_and_sorted(self) -> None:
        self.assertEqual(chunk_ports([443, 80, 443, 22]), [[22, 80, 443]])

    def test_batches_cover_input_exactly_once(self) -> None:
        ports = sorted(set([22, 443] + list(range(1000, 9000))))
        batches = chunk_ports(ports)
        flattened = [port for batch in batches for port in batch]
        self.assertEqual(flattened, ports)
        self.assertTrue(all(len(batch) <= BATCH_SIZE for batch in batches))

    def test_full_port_range_needs_32_batches(self) -> None:
        batches = chunk_ports(list(range(1, MAX_PORTS + 1)))
        self.assertEqual(len(batches), 32)
        self.assertEqual(batches[-1][-1], MAX_PORTS)
        self.assertEqual(sum(len(batch) for batch in batches), MAX_PORTS)


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
    """Giới hạn tổng số lượt thử của một job."""

    def test_one_host_full_range_is_allowed(self) -> None:
        self.assertLessEqual(1 * MAX_PORTS, MAX_ATTEMPTS)

    def test_slash_24_with_1024_ports_is_allowed(self) -> None:
        # Tương đương ví dụ 256 host × 1024 cổng.
        self.assertLessEqual(254 * 1024, MAX_ATTEMPTS)

    def test_slash_24_with_full_range_is_rejected(self) -> None:
        self.assertGreater(254 * MAX_PORTS, MAX_ATTEMPTS)

    def test_slash_24_with_2048_ports_is_rejected(self) -> None:
        self.assertGreater(254 * 2048, MAX_ATTEMPTS)

    def test_message_mentions_limit_and_how_to_reduce(self) -> None:
        message = attempt_limit_message(254, 65535)
        self.assertIn(str(MAX_ATTEMPTS), message)
        self.assertIn("254 host", message)
        self.assertIn("65535 cổng", message)
        self.assertIn("giảm số cổng", message)
        self.assertIn("thu nhỏ dải CIDR", message)


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


if __name__ == "__main__":
    unittest.main()