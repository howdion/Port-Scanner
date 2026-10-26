"""Xuất kết quả quét cổng ra báo cáo JSON/CSV."""

from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


CSV_FIELDS = ("host", "port", "protocol", "service", "banner", "scanned_at")


@dataclass(frozen=True)
class ScanRecord:
    """Một cổng mở trong báo cáo."""

    host: str
    port: int
    protocol: str
    service: str
    banner: str | None
    scanned_at: str


def render_report(
    report_format: str,
    records: Iterable[ScanRecord],
    metadata: dict[str, Any],
) -> str:
    """Dựng nội dung báo cáo JSON hoặc CSV thành chuỗi.

    Hàm này dùng chung cho cả CLI (ghi file) và web (tải về), nhờ vậy định dạng
    báo cáo chỉ được định nghĩa ở một chỗ.

    ``metadata`` do nơi gọi dựng bằng ``main.build_report_metadata``: ``target``
    là nhãn hiển thị (một IP hoặc "N host"), ``target_hosts`` là danh sách host
    thật đã quét, kèm ``hosts_count``, ``port_range``, ``total_open_ports`` và
    ``scan_duration_seconds``. Web server thêm ``batches_completed`` và
    ``batches_total``. Báo cáo CSV không có phần metadata, chỉ có các dòng kết quả.

    Raises:
        ValueError: Khi định dạng báo cáo không phải ``json`` hoặc ``csv``.
    """
    rows = list(records)
    buffer = io.StringIO()

    if report_format == "json":
        payload = {
            "metadata": metadata,
            "results": [asdict(record) for record in rows],
        }
        json.dump(payload, buffer, ensure_ascii=False, indent=2)
        buffer.write("\n")
    elif report_format == "csv":
        writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for record in rows:
            row = asdict(record)
            # csv tự động quote trường có dấu phẩy, xuống dòng hoặc dấu nháy.
            row["banner"] = record.banner or ""
            writer.writerow(row)
    else:
        raise ValueError(f"định dạng báo cáo không hợp lệ: {report_format}")

    return buffer.getvalue()


def write_report(
    path: Path,
    report_format: str,
    records: Iterable[ScanRecord],
    metadata: dict[str, Any],
) -> None:
    """Ghi báo cáo JSON hoặc CSV, tạo thư mục cha nếu cần.

    Báo cáo được ghi vào file tạm cùng thư mục rồi thay thế file đích, tránh
    để lại file dở dang nếu quá trình ghi gặp lỗi.

    Raises:
        OSError: Khi không tạo/ghi được thư mục hoặc file báo cáo.
        ValueError: Khi định dạng báo cáo không phải ``json`` hoặc ``csv``.
    """
    text = render_report(report_format, records, metadata)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
