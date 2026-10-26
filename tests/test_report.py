"""Kiểm thử xuất báo cáo JSON/CSV."""

from __future__ import annotations

import csv
import io
import json
import shutil
import sys
import unittest
import uuid
from pathlib import Path

# Cho phép chạy kiểm thử từ bất kỳ thư mục nào.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from report import CSV_FIELDS, ScanRecord, render_report, write_report  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRATCH_ROOT = REPO_ROOT / "reports"


class WorkspaceTempDir:
    """Thư mục tạm nằm trong workspace, tự xóa khi thoát.

    Không dùng ``tempfile.TemporaryDirectory``: trên Windows, thư mục mới tạo
    trong ``%TEMP%`` có thể không ghi được và việc xóa thư mục có thể bị chặn,
    khiến việc dọn dẹp treo. ``reports/`` đã nằm trong ``.gitignore`` nên dùng
    làm chỗ tạm là an toàn.
    """

    def __init__(self) -> None:
        SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
        self.path = SCRATCH_ROOT / f"test-report-{uuid.uuid4().hex[:12]}"
        self.path.mkdir(parents=True, exist_ok=True)

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, *exc_info: object) -> None:
        shutil.rmtree(self.path, ignore_errors=True)


def make_record(**overrides: object) -> ScanRecord:
    values: dict[str, object] = {
        "host": "127.0.0.1",
        "port": 135,
        "protocol": "tcp",
        "service": "msrpc",
        "banner": None,
        "scanned_at": "2026-10-26T00:00:00+07:00",
    }
    values.update(overrides)
    return ScanRecord(**values)  # type: ignore[arg-type]


METADATA = {
    "target": "127.0.0.1",
    "port_range": "135,445",
    "total_open_ports": 2,
    "scan_duration_seconds": 1.234,
}


class RenderJsonTest(unittest.TestCase):
    """Báo cáo JSON có metadata ở đầu và danh sách results."""

    def test_structure(self) -> None:
        records = [make_record(), make_record(port=445, service="microsoft-ds")]
        document = json.loads(render_report("json", records, METADATA))
        self.assertEqual(set(document), {"metadata", "results"})
        self.assertEqual(document["metadata"], METADATA)
        self.assertEqual(len(document["results"]), 2)
        self.assertEqual(
            set(document["results"][0]),
            {"host", "port", "protocol", "service", "banner", "scanned_at"},
        )

    def test_metadata_counts_open_ports(self) -> None:
        records = [make_record(port=port) for port in (135, 445, 5357)]
        metadata = dict(METADATA, total_open_ports=len(records))
        document = json.loads(render_report("json", records, metadata))
        self.assertEqual(document["metadata"]["total_open_ports"], 3)
        self.assertEqual(len(document["results"]), 3)

    def test_banner_none_becomes_null(self) -> None:
        document = json.loads(render_report("json", [make_record()], METADATA))
        self.assertIsNone(document["results"][0]["banner"])

    def test_unicode_is_kept_readable(self) -> None:
        record = make_record(service="dịch vụ", banner="Xin chào")
        text = render_report("json", [record], METADATA)
        self.assertIn("dịch vụ", text)
        self.assertNotIn("\\u1ecb", text)
        self.assertEqual(json.loads(text)["results"][0]["service"], "dịch vụ")

    def test_empty_results(self) -> None:
        document = json.loads(render_report("json", [], METADATA))
        self.assertEqual(document["results"], [])

    def test_ends_with_newline(self) -> None:
        self.assertTrue(render_report("json", [], METADATA).endswith("\n"))


class RenderCsvTest(unittest.TestCase):
    """Báo cáo CSV đúng cột và xử lý ký tự đặc biệt."""

    def test_header_and_rows(self) -> None:
        records = [make_record(), make_record(port=445, service="microsoft-ds")]
        text = render_report("csv", records, METADATA)
        reader = csv.DictReader(io.StringIO(text, newline=""))
        self.assertEqual(tuple(reader.fieldnames or ()), CSV_FIELDS)
        rows = list(reader)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["host"], "127.0.0.1")
        self.assertEqual(rows[0]["port"], "135")
        self.assertEqual(rows[1]["service"], "microsoft-ds")

    def test_none_banner_becomes_empty_field(self) -> None:
        text = render_report("csv", [make_record()], METADATA)
        rows = list(csv.DictReader(io.StringIO(text, newline="")))
        self.assertEqual(rows[0]["banner"], "")

    def test_banner_with_comma_newline_and_quote_round_trips(self) -> None:
        banner = 'Server: Test, Inc.\nSecond line "quoted"'
        text = render_report("csv", [make_record(banner=banner)], METADATA)
        rows = list(csv.DictReader(io.StringIO(text, newline="")))
        self.assertEqual(rows[0]["banner"], banner)
        # Trường có ký tự đặc biệt phải được quote.
        self.assertIn('"Server: Test, Inc.', text)

    def test_banner_with_html_is_data_not_markup(self) -> None:
        banner = "<img src=x onerror=alert(1)>"
        text = render_report("csv", [make_record(banner=banner)], METADATA)
        rows = list(csv.DictReader(io.StringIO(text, newline="")))
        self.assertEqual(rows[0]["banner"], banner)

    def test_utf8_content_is_preserved(self) -> None:
        text = render_report("csv", [make_record(service="dịch vụ")], METADATA)
        rows = list(csv.DictReader(io.StringIO(text, newline="")))
        self.assertEqual(rows[0]["service"], "dịch vụ")

    def test_uses_crlf_like_the_cli_report(self) -> None:
        text = render_report("csv", [make_record()], METADATA)
        self.assertIn("\r\n", text)


class RenderReportErrorTest(unittest.TestCase):
    """Định dạng không hợp lệ bị từ chối."""

    def test_unknown_format_raises_value_error(self) -> None:
        for value in ("xml", "JSON", "", "txt"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    render_report(value, [], METADATA)


class WriteReportTest(unittest.TestCase):
    """Ghi file dùng đúng nội dung mà render_report tạo ra."""

    def test_write_matches_render_bytes(self) -> None:
        records = [make_record(), make_record(port=445, banner='A, B\n"C"')]
        with WorkspaceTempDir() as tmp:
            for report_format in ("json", "csv"):
                with self.subTest(report_format=report_format):
                    path = tmp / f"report.{report_format}"
                    write_report(path, report_format, records, METADATA)
                    expected = render_report(report_format, records, METADATA)
                    self.assertEqual(path.read_bytes(), expected.encode("utf-8"))

    def test_write_creates_parent_directory(self) -> None:
        with WorkspaceTempDir() as tmp:
            path = tmp / "nested" / "deeper" / "report.json"
            self.assertFalse(path.parent.is_dir())
            write_report(path, "json", [make_record()], METADATA)
            self.assertTrue(path.is_file())
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(document["metadata"], METADATA)

    def test_write_overwrites_existing_file(self) -> None:
        with WorkspaceTempDir() as tmp:
            path = tmp / "report.json"
            path.write_text("nội dung cũ", encoding="utf-8")
            write_report(path, "json", [make_record(port=445)], METADATA)
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(document["results"][0]["port"], 445)

    def test_write_leaves_no_temp_file_behind(self) -> None:
        with WorkspaceTempDir() as tmp:
            path = tmp / "report.csv"
            write_report(path, "csv", [make_record()], METADATA)
            leftovers = [p.name for p in tmp.iterdir() if p.name != "report.csv"]
            self.assertEqual(leftovers, [])

    def test_write_with_bad_format_raises_without_creating_file(self) -> None:
        with WorkspaceTempDir() as tmp:
            path = tmp / "report.xml"
            with self.assertRaises(ValueError):
                write_report(path, "xml", [make_record()], METADATA)
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
