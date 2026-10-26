"""Kiểm thử hai mốc giới hạn tổng lượt quét và các hàm ước tính."""

from __future__ import annotations

import ipaddress
import sys
import unittest
from pathlib import Path

# Cho phép chạy kiểm thử từ bất kỳ thư mục nào.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import (  # noqa: E402
    CIDR_MIN_PREFIX,
    HARD_ATTEMPTS,
    WARN_ATTEMPTS,
    count_target_hosts,
    estimate_job_attempts,
    estimate_scan_seconds,
    format_attempts,
    format_duration,
    hard_limit_message,
    large_scan_lines,
)


def classify(attempts: int) -> str:
    """Phân loại một ước tính theo hai mốc, giống luồng kiểm tra của server."""
    if attempts > HARD_ATTEMPTS:
        return "rejected"
    if attempts > WARN_ATTEMPTS:
        return "confirm"
    return "run"


class ThresholdConstantsTest(unittest.TestCase):
    """Hai mốc đã chốt: cảnh báo 500.000 và trần cứng 5.000.000."""

    def test_warn_threshold(self) -> None:
        self.assertEqual(WARN_ATTEMPTS, 500_000)

    def test_hard_threshold(self) -> None:
        self.assertEqual(HARD_ATTEMPTS, 5_000_000)

    def test_min_cidr_prefix(self) -> None:
        self.assertEqual(CIDR_MIN_PREFIX, 18)


class CountHostsTest(unittest.TestCase):
    """Số host tối đa của mục tiêu."""

    def test_single_address(self) -> None:
        self.assertEqual(count_target_hosts(ipaddress.ip_address("127.0.0.1")), 1)

    def test_slash_18(self) -> None:
        self.assertEqual(count_target_hosts(ipaddress.ip_network("10.0.0.0/18")), 16382)

    def test_slash_24(self) -> None:
        self.assertEqual(count_target_hosts(ipaddress.ip_network("10.0.0.0/24")), 254)

    def test_slash_31_and_32(self) -> None:
        self.assertEqual(count_target_hosts(ipaddress.ip_network("10.0.0.0/31")), 2)
        self.assertEqual(count_target_hosts(ipaddress.ip_network("10.0.0.1/32")), 1)


class EstimateAttemptsTest(unittest.TestCase):
    """Tổng lượt quét dự kiến = số host × (cổng quét + cổng dò host)."""

    def test_single_host_without_discovery(self) -> None:
        self.assertEqual(estimate_job_attempts(1, 1024), 1024)

    def test_cidr_includes_discovery_ports(self) -> None:
        self.assertEqual(estimate_job_attempts(254, 1024, 5), 254 * 1029)

    def test_slash_18_full_range(self) -> None:
        self.assertEqual(
            estimate_job_attempts(16382, 65535, 5), 16382 * 65540
        )


class ClassificationTest(unittest.TestCase):
    """Ranh giới của hai mốc."""

    def test_just_below_warning_runs(self) -> None:
        self.assertEqual(classify(WARN_ATTEMPTS - 1), "run")
        self.assertEqual(classify(WARN_ATTEMPTS), "run")

    def test_just_above_warning_needs_confirmation(self) -> None:
        self.assertEqual(classify(WARN_ATTEMPTS + 1), "confirm")

    def test_at_hard_cap_still_allowed_with_confirmation(self) -> None:
        self.assertEqual(classify(HARD_ATTEMPTS), "confirm")

    def test_above_hard_cap_is_rejected(self) -> None:
        self.assertEqual(classify(HARD_ATTEMPTS + 1), "rejected")

    def test_one_host_full_range_runs_without_warning(self) -> None:
        self.assertEqual(classify(estimate_job_attempts(1, 65535)), "run")

    def test_slash_24_with_1024_ports_runs(self) -> None:
        self.assertEqual(classify(estimate_job_attempts(254, 1024, 5)), "run")

    def test_slash_24_with_2048_ports_needs_confirmation(self) -> None:
        self.assertEqual(classify(estimate_job_attempts(254, 2048, 5)), "confirm")

    def test_slash_24_with_full_range_is_rejected(self) -> None:
        self.assertEqual(classify(estimate_job_attempts(254, 65535, 5)), "rejected")

    def test_slash_18_with_full_range_is_rejected(self) -> None:
        attempts = estimate_job_attempts(16382, 65535, 5)
        self.assertEqual(classify(attempts), "rejected")
        self.assertGreater(attempts, 1_000_000_000)


class EstimateSecondsTest(unittest.TestCase):
    """Ước tính thời gian theo timeout và số luồng."""

    def test_scales_with_timeout_and_workers(self) -> None:
        one_worker = estimate_scan_seconds(1, 1000, 1.0, workers=1)
        ten_workers = estimate_scan_seconds(1, 1000, 1.0, workers=10)
        self.assertAlmostEqual(one_worker, 1000.0)
        self.assertAlmostEqual(ten_workers, 100.0)

    def test_includes_discovery_phase(self) -> None:
        without = estimate_scan_seconds(254, 1024, 1.0, workers=100)
        with_discovery = estimate_scan_seconds(254, 1024, 1.0, 5, 0.3, 100)
        self.assertGreater(with_discovery, without)

    def test_never_divides_by_zero(self) -> None:
        self.assertGreater(estimate_scan_seconds(1, 10, 1.0, workers=0), 0)


class FormattingTest(unittest.TestCase):
    """Định dạng số và thời gian theo kiểu Việt Nam."""

    def test_thousands_separator(self) -> None:
        self.assertEqual(format_attempts(500_000), "500.000")
        self.assertEqual(format_attempts(1_073_676_280), "1.073.676.280")

    def test_duration_units(self) -> None:
        self.assertEqual(format_duration(10), "10 giây")
        self.assertEqual(format_duration(2580), "43 phút")
        self.assertEqual(format_duration(5040), "1.4 giờ")
        # Từ 48 giờ trở lên mới đổi sang đơn vị ngày.
        self.assertEqual(format_duration(33.6 * 3600), "33.6 giờ")
        self.assertEqual(format_duration(4 * 24 * 3600), "4.0 ngày")


class MessageTest(unittest.TestCase):
    """Thông báo phải nêu rõ giới hạn và cách giảm."""

    def test_hard_limit_message(self) -> None:
        message = hard_limit_message(16382, 65535, 5)
        self.assertIn("5.000.000", message)
        self.assertIn("16382 host", message)
        self.assertIn("giảm số cổng", message)
        self.assertIn("thu nhỏ dải CIDR", message)

    def test_large_scan_lines_mention_threshold_and_time(self) -> None:
        lines = large_scan_lines(600_000, 3600)
        text = " ".join(lines)
        self.assertIn("600.000", text)
        self.assertIn("500.000", text)
        self.assertIn("1.0 giờ", text)
        self.assertIn("an ninh", text)


if __name__ == "__main__":
    unittest.main()
