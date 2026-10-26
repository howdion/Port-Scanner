"""Kiểm thử CLI hai giai đoạn: `discover` tách rời `scan`.

Mọi bài kiểm thử đều thay `discover_hosts`/`scan_ports`/`grab_banners` bằng
mock nên không mở kết nối mạng nào và chạy rất nhanh.
"""

from __future__ import annotations

import contextlib
import io
import ipaddress
import json
import shutil
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

# Cho phép chạy kiểm thử từ bất kỳ thư mục nào.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRATCH_ROOT = REPO_ROOT / "reports"


class CliTestCase(unittest.TestCase):
    """Chạy `main.main()` với tham số cho trước và mock toàn bộ phần mạng."""

    def setUp(self) -> None:
        SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
        self.workdir = SCRATCH_ROOT / f"test-cli-{uuid.uuid4().hex[:12]}"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, self.workdir, True)

    def invoke(
        self,
        argv: list[str],
        live_hosts: list[str] | None = None,
        open_ports: list[int] | None = None,
    ) -> tuple[int, str]:
        """Chạy CLI; trả về (mã thoát, toàn bộ stdout)."""
        output = io.StringIO()
        self.discover_mock = mock.Mock(return_value=list(live_hosts or []))
        self.scan_mock = mock.Mock(return_value=(list(open_ports or []), []))
        self.banner_mock = mock.Mock(return_value={})
        with mock.patch.object(sys, "argv", ["main.py", *argv]), \
                mock.patch.object(main, "discover_hosts", self.discover_mock), \
                mock.patch.object(main, "scan_ports", self.scan_mock), \
                mock.patch.object(main, "grab_banners", self.banner_mock), \
                mock.patch.object(main, "stdin_is_interactive", return_value=False), \
                contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(io.StringIO()):
            code = main.main()
        return code, output.getvalue()

    def write_hosts_file(self, payload: object) -> Path:
        path = self.workdir / "hosts.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path


class DiscoverCommandTest(CliTestCase):
    """`discover` chỉ dò host sống, không quét cổng."""

    def test_discover_does_not_scan_ports(self) -> None:
        code, text = self.invoke(
            ["discover", "127.0.0.0/28"], live_hosts=["127.0.0.1", "127.0.0.2"]
        )

        self.assertEqual(code, 0)
        self.discover_mock.assert_called_once()
        self.scan_mock.assert_not_called()
        self.assertIn("Tìm thấy 2/14 host sống", text)
        self.assertIn("127.0.0.1", text)
        self.assertIn("127.0.0.2", text)

    def test_discover_uses_concurrency_option(self) -> None:
        code, _ = self.invoke(["discover", "127.0.0.0/28", "--concurrency", "7"])

        self.assertEqual(code, 0)
        self.assertEqual(
            self.discover_mock.call_args.kwargs["workers"], 7
        )

    def test_discover_writes_json_file(self) -> None:
        output = self.workdir / "live.json"
        code, text = self.invoke(
            ["discover", "127.0.0.0/28", "--output", str(output)],
            live_hosts=["127.0.0.1"],
        )

        self.assertEqual(code, 0)
        self.assertIn("Đã ghi danh sách host sống", text)
        data = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(
            set(data), {"cidr", "discovery_ports", "discovered_at", "live_hosts"}
        )
        self.assertEqual(data["cidr"], "127.0.0.0/28")
        self.assertEqual(data["discovery_ports"], "22,80,135,443,445")
        self.assertEqual(data["live_hosts"], ["127.0.0.1"])
        self.assertTrue(data["discovered_at"])

    def test_discover_rejects_a_single_ip(self) -> None:
        code, text = self.invoke(["discover", "127.0.0.1"])

        self.assertEqual(code, 1)
        self.assertIn("CIDR", text)
        self.discover_mock.assert_not_called()

    def test_discover_rejects_external_cidr_without_yes(self) -> None:
        code, text = self.invoke(["discover", "8.8.8.0/24"])

        self.assertEqual(code, 1)
        self.assertIn("không nằm trong dải IP nội bộ", text)
        self.discover_mock.assert_not_called()

    def test_discover_rejects_cidr_larger_than_slash_18(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            self.invoke(["discover", "10.0.0.0/16"])
        self.assertEqual(caught.exception.code, 2)


class ScanCommandTest(CliTestCase):
    """`scan` quét cổng trên host đã biết, không nhận CIDR."""

    def test_scan_rejects_cidr_target(self) -> None:
        code, text = self.invoke(["scan", "127.0.0.0/24", "--ports", "135"])

        self.assertEqual(code, 1)
        self.assertIn(main.SCAN_CIDR_HINT, text)
        self.scan_mock.assert_not_called()

    def test_scan_single_ip_works(self) -> None:
        code, text = self.invoke(
            ["scan", "127.0.0.1", "--ports", "135,445"], open_ports=[135, 445]
        )

        self.assertEqual(code, 0)
        self.scan_mock.assert_called_once()
        self.assertEqual(self.scan_mock.call_args.args[0], "127.0.0.1")
        self.assertIn("Cổng mở trên 127.0.0.1", text)

    def test_scan_hosts_option(self) -> None:
        code, text = self.invoke(
            ["scan", "--hosts", "127.0.0.1,127.0.0.2", "--ports", "135"]
        )

        self.assertEqual(code, 0)
        self.assertEqual(self.scan_mock.call_count, 2)
        self.assertIn("Tổng cộng: 2 host", text)

    def test_scan_reads_hosts_file(self) -> None:
        path = self.write_hosts_file(
            {
                "cidr": "127.0.0.0/28",
                "discovery_ports": "135",
                "discovered_at": "2026-10-26T10:00:00+07:00",
                "live_hosts": ["127.0.0.1", "127.0.0.3"],
            }
        )
        code, text = self.invoke(
            ["scan", "--hosts-file", str(path), "--ports", "135"]
        )

        self.assertEqual(code, 0)
        self.assertEqual(self.scan_mock.call_count, 2)
        self.assertIn("Tổng cộng: 2 host", text)

    def test_scan_rejects_external_host_in_list(self) -> None:
        code, text = self.invoke(
            ["scan", "--hosts", "127.0.0.1,8.8.8.8", "--ports", "80"]
        )

        self.assertEqual(code, 1)
        self.assertIn("8.8.8.8", text)
        self.assertIn("ngoài dải nội bộ", text)
        self.scan_mock.assert_not_called()

    def test_scan_rejects_cidr_inside_hosts(self) -> None:
        code, text = self.invoke(["scan", "--hosts", "127.0.0.0/28", "--ports", "80"])

        self.assertEqual(code, 1)
        self.assertIn("không nhận CIDR", text)
        self.scan_mock.assert_not_called()

    def test_scan_requires_exactly_one_target_source(self) -> None:
        code, text = self.invoke(["scan", "--ports", "80"])
        self.assertEqual(code, 1)
        self.assertIn("cần một mục tiêu", text)

        path = self.write_hosts_file({"live_hosts": ["127.0.0.1"]})
        code, text = self.invoke(
            [
                "scan",
                "127.0.0.1",
                "--hosts-file",
                str(path),
                "--ports",
                "80",
            ]
        )
        self.assertEqual(code, 1)
        self.assertIn("chỉ được dùng một nguồn host", text)
        self.scan_mock.assert_not_called()

    def test_scan_reports_bad_hosts_file(self) -> None:
        path = self.workdir / "hong.json"
        path.write_text("{khong-phai-json", encoding="utf-8")
        code, text = self.invoke(["scan", "--hosts-file", str(path), "--ports", "80"])

        self.assertEqual(code, 1)
        self.assertIn("không phải JSON hợp lệ", text)
        self.scan_mock.assert_not_called()

    def test_scan_rejects_hosts_file_without_live_hosts(self) -> None:
        path = self.write_hosts_file({"cidr": "127.0.0.0/28"})
        code, text = self.invoke(["scan", "--hosts-file", str(path), "--ports", "80"])

        self.assertEqual(code, 1)
        self.assertIn("live_hosts", text)
        self.scan_mock.assert_not_called()


class BackwardCompatibilityTest(CliTestCase):
    """Cách gọi cũ `main.py <IP>` vẫn chạy như `scan` với một IP đơn."""

    def test_legacy_single_ip_scans(self) -> None:
        code, text = self.invoke(
            ["127.0.0.1", "--ports", "135,445"], open_ports=[135]
        )

        self.assertEqual(code, 0)
        self.scan_mock.assert_called_once()
        self.assertEqual(self.scan_mock.call_args.args[0], "127.0.0.1")
        self.assertNotIn(main.STAGE_LABELS[main.STAGE_DISCOVERY], text)

    def test_no_arguments_scans_localhost(self) -> None:
        code, _ = self.invoke([])

        self.assertEqual(code, 0)
        self.scan_mock.assert_called_once()
        self.assertEqual(self.scan_mock.call_args.args[0], "127.0.0.1")

    def test_legacy_cidr_is_rejected_with_hint(self) -> None:
        code, text = self.invoke(["127.0.0.0/24", "--ports", "135"])

        self.assertEqual(code, 1)
        self.assertIn(main.SCAN_CIDR_HINT, text)
        self.scan_mock.assert_not_called()

    def test_help_lists_both_subcommands(self) -> None:
        help_output = io.StringIO()
        with mock.patch.object(sys, "argv", ["main.py", "--help"]), \
                contextlib.redirect_stdout(help_output):
            code = main.main()

        self.assertEqual(code, 0)
        text = help_output.getvalue()
        self.assertIn("discover", text)
        self.assertIn("scan", text)


class ReportMetadataTest(unittest.TestCase):
    """Metadata báo cáo: giữ `target` cũ và thêm `target_hosts` cho danh sách."""

    def test_single_host_keeps_old_shape(self) -> None:
        metadata = main.build_report_metadata(
            [ipaddress.ip_address("127.0.0.1")], [135], [], 1.5
        )

        self.assertEqual(metadata["target"], "127.0.0.1")
        self.assertEqual(metadata["target_hosts"], ["127.0.0.1"])
        self.assertEqual(metadata["hosts_count"], 1)
        self.assertEqual(metadata["port_range"], "135")
        self.assertEqual(metadata["total_open_ports"], 0)
        self.assertEqual(metadata["scan_duration_seconds"], 1.5)

    def test_multi_host_adds_list_and_keeps_old_fields(self) -> None:
        hosts = [
            ipaddress.ip_address("127.0.0.1"),
            ipaddress.ip_address("127.0.0.2"),
        ]
        metadata = main.build_report_metadata(hosts, [135, 445], [], 2.0)

        self.assertEqual(metadata["target"], "2 host")
        self.assertEqual(metadata["target_hosts"], ["127.0.0.1", "127.0.0.2"])
        self.assertEqual(metadata["hosts_count"], 2)
        self.assertEqual(metadata["port_range"], "135,445")
        self.assertEqual(metadata["total_open_ports"], 0)


class ReportFileTest(CliTestCase):
    """`scan --output` ghi metadata chứa danh sách host thật."""

    def test_scan_report_contains_target_hosts(self) -> None:
        output = self.workdir / "report.json"
        code, _ = self.invoke(
            [
                "scan",
                "--hosts",
                "127.0.0.1,127.0.0.2",
                "--ports",
                "135",
                "--output",
                str(output),
            ],
            open_ports=[135],
        )

        self.assertEqual(code, 0)
        data = json.loads(output.read_text(encoding="utf-8"))
        metadata = data["metadata"]
        self.assertEqual(metadata["target"], "2 host")
        self.assertEqual(metadata["target_hosts"], ["127.0.0.1", "127.0.0.2"])
        self.assertEqual(metadata["hosts_count"], 2)
        self.assertEqual(metadata["port_range"], "135")
        self.assertEqual(metadata["total_open_ports"], 2)
        self.assertEqual(len(data["results"]), 2)


if __name__ == "__main__":
    unittest.main()
