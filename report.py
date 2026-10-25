"""Xuất kết quả quét cổng ra báo cáo JSON/CSV."""

from __future__ import annotations

import csv
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
    rows = list(records)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            if report_format == "json":
                payload = {
                    "metadata": metadata,
                    "results": [asdict(record) for record in rows],
                }
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            elif report_format == "csv":
                writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
                writer.writeheader()
                for record in rows:
                    row = asdict(record)
                    # csv tự động quote trường có dấu phẩy, xuống dòng hoặc dấu nháy.
                    row["banner"] = record.banner or ""
                    writer.writerow(row)
            else:
                raise ValueError(f"định dạng báo cáo không hợp lệ: {report_format}")
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
