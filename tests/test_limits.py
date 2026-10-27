"""Kiểm thử hai mốc giới hạn cho TỪNG giai đoạn và các hàm ước tính."""

from __future__ import annotations

import contextlib
import io
import ipaddress
import sys
import unittest
from pathlib import Path
from unittest import mock

# Cho phép chạy kiểm thử từ bất kỳ thư mục nào.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main  # noqa: E402
from main import (  # noqa: E402
    CIDR_MIN_PREFIX,
    HARD_ATTEMPTS,
    STAGE_DISCOVERY,
    STAGE_LABELS,
    STAGE_SCAN,
    WARN_ATTEMPTS,
    count_target_hosts,
    estimate_stage_attempts,
    estimate_stage_seconds,
    format_attempts,
    format_duration,
    stage_limit_message,
    stage_warning_lines,
)


def classify(attempts: int) -> str:
    """Phân loại một ước tính của MỘT giai đoạn theo hai mốc."""
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

    def test_stage_labels_are_distinct(self) -> None:
        self.assertIn("dò host", STAGE_LABELS[STAGE_DISCOVERY])
        self.assertIn("quét cổng", STAGE_LABELS[STAGE_SCAN])
        self.assertNotEqual(
            STAGE_LABELS[STAGE_DISCOVERY], STAGE_LABELS[STAGE_SCAN]
        )


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


class StageAttemptsTest(unittest.TestCase):
    """Mỗi giai đoạn chỉ tính lượt của chính nó, không cộng giai đoạn kia."""

    def test_single_host_without_discovery(self) -> None:
        self.assertEqual(estimate_stage_attempts(1, 1024), 1024)

    def test_discovery_stage_excludes_scan_ports(self) -> None:
        self.assertEqual(estimate_stage_attempts(254, 5), 254 * 5)

    def test_scan_stage_excludes_discovery_ports(self) -> None:
        self.assertEqual(estimate_stage_attempts(254, 1024), 254 * 1024)

    def test_slash_18_stage_estimates(self) -> None:
        self.assertEqual(estimate_stage_attempts(16382, 5), 81_910)
        self.assertEqual(estimate_stage_attempts(16382, 1024), 16_775_168)

    def test_matches_simple_product(self) -> None:
        for hosts, ports in ((1, 1), (254, 1024), (16382, 65535)):
            with self.subTest(hosts=hosts, ports=ports):
                self.assertEqual(
                    estimate_stage_attempts(hosts, ports), hosts * ports
                )


class StageSeparationTest(unittest.TestCase):
    """Trường hợp /18 × 1024 cổng: hai giai đoạn được đánh giá độc lập."""

    def setUp(self) -> None:
        self.hosts = count_target_hosts(ipaddress.ip_network("127.0.0.0/18"))
        self.discovery = estimate_stage_attempts(self.hosts, 5)
        self.scan = estimate_stage_attempts(self.hosts, 1024)

    def test_discovery_stage_is_under_the_thresholds(self) -> None:
        self.assertEqual(self.discovery, 81_910)
        self.assertEqual(classify(self.discovery), "run")

    def test_scan_stage_exceeds_the_hard_cap(self) -> None:
        self.assertEqual(self.scan, 16_775_168)
        self.assertEqual(classify(self.scan), "rejected")

    def test_discovery_is_not_rejected_because_of_the_scan_stage(self) -> None:
        # Nếu cộng dồn, giai đoạn dò cũng bị kéo theo con số khổng lồ của giai
        # đoạn quét. Kiểm tra độc lập thì giai đoạn dò vẫn được phép chạy.
        self.assertEqual(classify(self.discovery), "run")

    def test_no_stage_ever_uses_the_sum(self) -> None:
        self.assertNotEqual(self.discovery, self.discovery + self.scan)
        self.assertNotEqual(
            estimate_stage_attempts(self.hosts, 1024), self.discovery + self.scan
        )


class ClassificationTest(unittest.TestCase):
    """Ranh giới của hai mốc cho từng giai đoạn."""

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
        self.assertEqual(classify(estimate_stage_attempts(1, 65535)), "run")

    def test_slash_24_with_1024_ports_runs(self) -> None:
        self.assertEqual(classify(estimate_stage_attempts(254, 1024)), "run")

    def test_slash_24_with_2048_ports_needs_confirmation(self) -> None:
        self.assertEqual(classify(estimate_stage_attempts(254, 2048)), "confirm")

    def test_slash_24_with_full_range_is_rejected(self) -> None:
        self.assertEqual(classify(estimate_stage_attempts(254, 65535)), "rejected")

    def test_slash_18_discovery_ports_need_confirmation(self) -> None:
        # 16382 × 64 = 1.048.448: vượt mốc cảnh báo nhưng chưa tới trần cứng.
        self.assertEqual(classify(estimate_stage_attempts(16382, 64)), "confirm")


class EstimateSecondsTest(unittest.TestCase):
    """Ước tính thời gian của một giai đoạn theo timeout và số luồng."""

    def test_scales_with_timeout_and_workers(self) -> None:
        one_worker = estimate_stage_seconds(1, 1000, 1.0, workers=1)
        ten_workers = estimate_stage_seconds(1, 1000, 1.0, workers=10)
        self.assertAlmostEqual(one_worker, 1000.0)
        self.assertAlmostEqual(ten_workers, 100.0)

    def test_stage_uses_its_own_timeout(self) -> None:
        discovery = estimate_stage_seconds(254, 5, 0.3, workers=100)
        scan = estimate_stage_seconds(254, 1024, 1.0, workers=100)
        self.assertAlmostEqual(discovery, 254 * 5 * 0.3 / 100)
        self.assertAlmostEqual(scan, 254 * 1024 * 1.0 / 100)

    def test_never_divides_by_zero(self) -> None:
        self.assertGreater(estimate_stage_seconds(1, 10, 1.0, workers=0), 0)


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
    """Thông báo phải nêu rõ giai đoạn nào vượt và cách giảm."""

    def test_scan_stage_message(self) -> None:
        message = stage_limit_message(STAGE_SCAN, 100, 65535)
        self.assertIn("5.000.000", message)
        self.assertIn("giai đoạn quét cổng", message)
        self.assertIn("6.553.500", message)
        self.assertIn("100 host", message)
        self.assertIn("giảm số cổng", message)
        self.assertIn("bớt host", message)

    def test_discovery_stage_message(self) -> None:
        message = stage_limit_message(STAGE_DISCOVERY, 16382, 64)
        self.assertIn("giai đoạn dò host sống", message)
        self.assertIn("1.048.448", message)
        self.assertIn("cổng dò host", message)

    def test_warning_lines_mention_stage_threshold_and_time(self) -> None:
        lines = stage_warning_lines(STAGE_SCAN, 600_000, 3600)
        text = " ".join(lines)
        self.assertIn("giai đoạn quét cổng", text)
        self.assertIn("600.000", text)
        self.assertIn("500.000", text)
        self.assertIn("1.0 giờ", text)
        self.assertIn("an ninh", text)


class CliStageSeparationTest(unittest.TestCase):
    """Mỗi subcommand tự kiểm tra giới hạn bằng số host THẬT của nó."""

    def invoke(self, argv: list[str]):
        """Chạy CLI với mock mạng; trả về (mã thoát, stdout, mock dò, mock quét)."""
        output = io.StringIO()
        discover = mock.Mock(return_value=[])
        scan = mock.Mock(return_value=([], []))
        with mock.patch.object(sys, "argv", ["main.py", *argv]), \
                mock.patch.object(main, "discover_hosts", discover), \
                mock.patch.object(main, "scan_targets", scan), \
                mock.patch.object(main, "stdin_is_interactive", return_value=False), \
                contextlib.redirect_stdout(output):
            code = main.main()
        return code, output.getvalue(), discover, scan

    def test_discover_hard_cap_uses_max_hosts(self) -> None:
        # 16.382 host × 1.000 cổng dò = 16.382.000 > 5.000.000.
        code, text, discover, _ = self.invoke(
            ["discover", "127.0.0.0/18", "--discovery-ports", "1-1000"]
        )

        self.assertEqual(code, 1)
        self.assertIn(STAGE_LABELS[STAGE_DISCOVERY], text)
        self.assertIn("16.382.000", text)
        discover.assert_not_called()

    def test_discover_warn_is_acknowledged_by_flag(self) -> None:
        # 16.382 × 64 = 1.048.448 lượt dò: vượt cảnh báo, cần xác nhận.
        discovery_ports = ",".join(str(port) for port in range(1000, 1064))
        code, text, discover, _ = self.invoke(
            [
                "discover",
                "127.0.0.0/18",
                "--discovery-ports",
                discovery_ports,
                "--confirm-large-scan",
            ]
        )

        self.assertEqual(code, 0)
        self.assertIn(STAGE_LABELS[STAGE_DISCOVERY], text)
        self.assertIn("1.048.448", text)
        discover.assert_called_once()

    def test_scan_hard_cap_uses_real_host_count(self) -> None:
        # 100 host × 65.535 cổng = 6.553.500 > 5.000.000.
        hosts = ",".join(f"127.0.0.{index}" for index in range(1, 101))
        code, text, _, scan = self.invoke(
            ["scan", "--hosts", hosts, "--ports", "1-65535"]
        )

        self.assertEqual(code, 1)
        self.assertIn("6.553.500", text)
        self.assertIn("giai đoạn quét cổng", text)
        scan.assert_not_called()

    def test_scan_warn_requires_confirmation(self) -> None:
        # 14 host × 65.535 = 917.490: vượt cảnh báo, dưới trần cứng.
        hosts = ",".join(f"127.0.0.{index}" for index in range(1, 15))
        code, text, _, scan = self.invoke(
            ["scan", "--hosts", hosts, "--ports", "1-65535"]
        )

        self.assertEqual(code, 1)
        self.assertIn("917.490", text)
        self.assertIn("--confirm-large-scan", text)
        scan.assert_not_called()

    def test_scan_warn_is_acknowledged_by_flag(self) -> None:
        hosts = ",".join(f"127.0.0.{index}" for index in range(1, 15))
        code, text, _, scan = self.invoke(
            [
                "scan",
                "--hosts",
                hosts,
                "--ports",
                "1-65535",
                "--confirm-large-scan",
            ]
        )

        self.assertEqual(code, 0)
        self.assertIn("917.490", text)
        # Một lượt quét streaming duy nhất cho toàn bộ danh sách host.
        self.assertEqual(scan.call_count, 1)


if __name__ == "__main__":
    unittest.main()
