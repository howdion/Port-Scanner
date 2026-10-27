"""Kiểm thử phân tích mục tiêu và dải cổng."""

from __future__ import annotations

import argparse
import ipaddress
import sys
import unittest
from pathlib import Path

# Cho phép chạy kiểm thử từ bất kỳ thư mục nào.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import (  # noqa: E402
    format_port_spec,
    is_internal,
    parse_ports,
    parse_target,
)


class ParsePortsTest(unittest.TestCase):
    """Phân tích dải cổng: '80', '1-1024' hoặc '22,80,443'."""

    def test_single_port(self) -> None:
        self.assertEqual(parse_ports("80"), [80])

    def test_port_range(self) -> None:
        self.assertEqual(parse_ports("1-5"), [1, 2, 3, 4, 5])

    def test_comma_separated_list(self) -> None:
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_mixed_list_and_ranges(self) -> None:
        self.assertEqual(parse_ports("22,80-82,443"), [22, 80, 81, 82, 443])

    def test_whitespace_is_ignored(self) -> None:
        self.assertEqual(parse_ports(" 22 , 80 "), [22, 80])

    def test_duplicates_are_removed_keeping_order(self) -> None:
        self.assertEqual(parse_ports("443,80,443,80"), [443, 80])

    def test_boundary_ports(self) -> None:
        self.assertEqual(parse_ports("1"), [1])
        self.assertEqual(parse_ports("65535"), [65535])
        self.assertEqual(parse_ports("65535-65535"), [65535])

    def test_invalid_values_raise(self) -> None:
        invalid = (
            "",
            " ",
            "0",
            "65536",
            "0-10",
            "1-99999",
            "10-1",
            "abc",
            "80,,443",
            "1-2-3",
            "-5",
            "80-",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    parse_ports(value)


class ParseTargetTest(unittest.TestCase):
    """Phân tích mục tiêu: IPv4 hoặc CIDR IPv4 từ /18 đến /32."""

    def test_single_ipv4(self) -> None:
        target = parse_target("192.168.1.10")
        self.assertIsInstance(target, ipaddress.IPv4Address)
        self.assertEqual(str(target), "192.168.1.10")

    def test_cidr_slash_24(self) -> None:
        target = parse_target("192.168.1.0/24")
        self.assertIsInstance(target, ipaddress.IPv4Network)
        self.assertEqual(target.prefixlen, 24)

    def test_cidr_with_host_bits_is_normalized(self) -> None:
        target = parse_target("192.168.1.77/24")
        self.assertEqual(str(target), "192.168.1.0/24")

    def test_cidr_slash_30(self) -> None:
        self.assertEqual(str(parse_target("127.0.0.0/30")), "127.0.0.0/30")

    def test_cidr_slash_18_at_the_boundary(self) -> None:
        target = parse_target("10.0.0.0/18")
        self.assertIsInstance(target, ipaddress.IPv4Network)
        self.assertEqual(target.prefixlen, 18)

    def test_cidr_slash_32_is_allowed(self) -> None:
        self.assertEqual(str(parse_target("10.1.2.3/32")), "10.1.2.3/32")

    def test_cidr_larger_than_slash_18_is_rejected(self) -> None:
        for value in ("10.0.0.0/17", "10.0.0.0/16", "0.0.0.0/0", "127.0.0.0/8"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError) as ctx:
                    parse_target(value)
                self.assertIn("/18", str(ctx.exception))

    def test_cidr_slash_23_is_allowed_now(self) -> None:
        # /23 nằm trong khoảng cho phép mới (/18 đến /32).
        self.assertEqual(str(parse_target("192.168.0.0/23")), "192.168.0.0/23")

    def test_invalid_targets_raise(self) -> None:
        for value in ("999.999.999.999", "khong-phai-ip", "192.168.1", "", "1.2.3.4/"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    parse_target(value)

    def test_ipv6_is_rejected(self) -> None:
        for value in ("::1", "2001:db8::1", "fd00::/120"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError) as ctx:
                    parse_target(value)
                self.assertIn("IPv4", str(ctx.exception))


class FormatPortSpecTest(unittest.TestCase):
    """Rút gọn danh sách cổng để ghi vào metadata báo cáo."""

    def test_empty_list(self) -> None:
        self.assertEqual(format_port_spec([]), "")

    def test_single_port(self) -> None:
        self.assertEqual(format_port_spec([80]), "80")

    def test_contiguous_range(self) -> None:
        self.assertEqual(format_port_spec([1, 2, 3, 4]), "1-4")

    def test_mixed_ranges_and_singles(self) -> None:
        self.assertEqual(format_port_spec([1, 2, 3, 5]), "1-3,5")
        self.assertEqual(format_port_spec([22, 80, 443]), "22,80,443")

    def test_unsorted_and_duplicated_input(self) -> None:
        self.assertEqual(format_port_spec([5, 3, 1, 2, 3]), "1-3,5")


class IsInternalTest(unittest.TestCase):
    """Chỉ các dải nội bộ mới được coi là hợp lệ."""

    def test_internal_addresses(self) -> None:
        for value in ("127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.1"):
            with self.subTest(value=value):
                self.assertTrue(is_internal(ipaddress.ip_address(value)))

    def test_external_addresses(self) -> None:
        for value in ("8.8.8.8", "1.1.1.1", "172.32.0.1", "192.169.0.1", "11.0.0.1"):
            with self.subTest(value=value):
                self.assertFalse(is_internal(ipaddress.ip_address(value)))

    def test_internal_networks(self) -> None:
        self.assertTrue(is_internal(ipaddress.ip_network("192.168.1.0/24")))
        self.assertTrue(is_internal(ipaddress.ip_network("10.0.0.0/24")))
        self.assertTrue(is_internal(ipaddress.ip_network("127.0.0.0/30")))

    def test_external_networks(self) -> None:
        self.assertFalse(is_internal(ipaddress.ip_network("8.8.8.0/24")))
        # Nằm trong 172.16.0.0/12? Không: 172.32 vượt khỏi dải.
        self.assertFalse(is_internal(ipaddress.ip_network("172.32.0.0/24")))

    def test_network_spanning_internal_and_external_is_not_internal(self) -> None:
        # 11.0.0.0/8 không nằm trong dải nội bộ nào.
        self.assertFalse(is_internal(ipaddress.ip_network("11.0.0.0/24")))


if __name__ == "__main__":
    unittest.main()
