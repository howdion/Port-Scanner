"""Web server cục bộ hiển thị kết quả quét cổng.

Chỉ dùng thư viện chuẩn của Python. Server chỉ bind vào 127.0.0.1 và không có
tham số nào để đổi điều này, vì nếu mở ra mạng LAN thì người khác có thể dùng
máy của bạn để quét cổng.

Cách chạy:
    .venv\\Scripts\\python.exe web_server.py --port 8000
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import secrets
import sys
import threading
import time
import uuid
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from main import (
    HARD_ATTEMPTS,
    STAGE_DISCOVERY,
    STAGE_LABELS,
    STAGE_SCAN,
    WARN_ATTEMPTS,
    build_records,
    configure_output_encoding,
    count_target_hosts,
    current_timestamp,
    estimate_stage_attempts,
    estimate_stage_seconds,
    format_attempts,
    format_duration,
    format_port_spec,
    is_internal,
    parse_ports,
    parse_target,
    stage_limit_message,
    stage_warning_lines,
)
from report import ScanRecord, render_report
from scanner import DISCOVERY_PORTS, discover_hosts, grab_banners, scan_ports


# Bắt buộc: chỉ lắng nghe trên loopback, không bao giờ bind ra ngoài.
BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8000

# Token chống CSRF: sinh mỗi lần khởi động và bắt buộc với mọi request POST.
TOKEN_HEADER = "X-Scan-Token"

# Giới hạn phía server, không tin giá trị do trình duyệt gửi lên.
MAX_PORTS = 65535
# Kích thước một lô cổng: danh sách cổng được chia thành các lô liên tiếp cỡ này.
BATCH_SIZE = 2048
MAX_WORKERS = 100
DEFAULT_WORKERS = 100
MAX_DISCOVERY_PORTS = 64
MAX_BODY_BYTES = 65536
KEEP_JOBS = 20

# Giá trị mặc định và khoảng hợp lệ cho các tham số nâng cao. Giá trị gửi từ
# trình duyệt luôn được kiểm tra lại theo các khoảng này.
DEFAULT_SCAN_TIMEOUT = 1.0
DEFAULT_BANNER_TIMEOUT = 0.5
DEFAULT_DISCOVERY_TIMEOUT = 0.3
MIN_TIMEOUT = 0.05
MAX_TIMEOUT = 10.0

WEB_DIR = Path(__file__).resolve().parent / "web"
INDEX_FILE = WEB_DIR / "index.html"
TOKEN_PLACEHOLDER = "__SCAN_TOKEN__"
WARN_PLACEHOLDER = "__WARN_ATTEMPTS__"
HARD_PLACEHOLDER = "__HARD_ATTEMPTS__"

# Trang chỉ dùng tài nguyên nội tuyến nên CSP có thể siết rất chặt.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "style-src 'unsafe-inline'; "
    "script-src 'unsafe-inline'; "
    "connect-src 'self'; "
    "img-src 'none'; "
    "form-action 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)


class ApiError(Exception):
    """Lỗi trả về cho client dưới dạng JSON, không kèm traceback."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def chunk_ports(ports: list[int]) -> list[list[int]]:
    """Chia danh sách cổng thành các lô liên tiếp, mỗi lô tối đa BATCH_SIZE cổng.

    Danh sách được sắp xếp và loại trùng trước khi chia, nên các lô luôn liên
    tiếp nhau và không chồng lấn.
    """
    ordered = sorted(set(ports))
    return [
        ordered[index:index + BATCH_SIZE]
        for index in range(0, len(ordered), BATCH_SIZE)
    ]


def sort_records(records: list[ScanRecord]) -> list[ScanRecord]:
    """Sắp xếp kết quả theo địa chỉ IP (so sánh số) rồi theo cổng."""

    def key(record: ScanRecord) -> tuple[int, int]:
        try:
            return (int(ipaddress.IPv4Address(record.host)), record.port)
        except ValueError:
            # Không phải IPv4 (không xảy ra với dữ liệu hiện tại): xếp cuối.
            return (1 << 32, record.port)

    return sorted(records, key=key)


class ScanJob:
    """Trạng thái và kết quả của một lần quét chạy ở thread nền."""

    def __init__(
        self,
        target: ipaddress.IPv4Address | ipaddress.IPv4Network,
        ports: list[int],
        workers: int = DEFAULT_WORKERS,
        timeout: float = DEFAULT_SCAN_TIMEOUT,
        banner_timeout: float = DEFAULT_BANNER_TIMEOUT,
        discovery_timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
        discovery_ports: tuple[int, ...] = DISCOVERY_PORTS,
        confirmed_large_scan: bool = False,
    ) -> None:
        self.id = uuid.uuid4().hex
        self.target = target
        self.ports = list(ports)
        # Tham số nâng cao đã được server kiểm tra, dùng cho cả job này.
        self.workers = workers
        self.timeout = timeout
        self.banner_timeout = banner_timeout
        self.discovery_timeout = discovery_timeout
        self.discovery_ports = tuple(discovery_ports)
        self.confirmed_large_scan = confirmed_large_scan
        # Chia lô ngay khi tạo job để snapshot đầu tiên đã có đủ thông tin lô.
        self.batches = chunk_ports(self.ports)
        self.status = "running"
        self.phase = "starting"
        self.done = 0
        self.total = len(ports)
        self.message = "Đang khởi động..."
        self.records: list[ScanRecord] = []
        self.errors: list[str] = []
        self.started_at = current_timestamp()
        self.finished_at: str | None = None
        self.cancel_event = threading.Event()
        self._lock = threading.Lock()
        # Tiến độ theo lô: batch_index là lô đang chạy (1-based), ports_done là
        # số cổng đã quét xong trên tổng số cổng của cả job.
        self.batch_index = 0
        self.batch_total = len(self.batches)
        self.batch_port_range = ""
        self.ports_total = len(self.ports)
        self.ports_done = 0
        self.batches_completed = 0
        self._started_monotonic = time.perf_counter()
        self._duration: float | None = None

    def update(self, **fields: object) -> None:
        """Cập nhật thuộc tính trạng thái một cách an toàn giữa các luồng."""
        with self._lock:
            for key, value in fields.items():
                setattr(self, key, value)

    def progress(
        self,
        message: str,
        done: int,
        total: int,
        phase: str,
    ) -> None:
        """Cập nhật dòng tiến độ hiển thị trên giao diện."""
        self.update(message=message, done=done, total=total, phase=phase)

    def add_records(self, records: list[ScanRecord]) -> None:
        with self._lock:
            self.records.extend(records)

    def records_snapshot(self) -> list[ScanRecord]:
        with self._lock:
            return list(self.records)

    def records_for_report(self) -> list[ScanRecord]:
        """Kết quả đã sắp xếp, dùng cho cả snapshot API lẫn file tải về."""
        return sort_records(self.records_snapshot())

    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def mark_finished(self, status: str, message: str) -> None:
        """Chốt trạng thái cuối của lần quét."""
        with self._lock:
            self.status = status
            self.message = message
            self.finished_at = current_timestamp()
            self._duration = time.perf_counter() - self._started_monotonic

    def report_metadata(self) -> dict:
        """Metadata của báo cáo, tính tại thời điểm gọi.

        Nhờ vậy vẫn tải được báo cáo khi job đang chạy hoặc đã bị hủy, và số lô
        đã hoàn thành luôn đúng với thời điểm tải.
        """
        with self._lock:
            duration = self._duration
            if duration is None:
                duration = time.perf_counter() - self._started_monotonic
            return {
                "target": str(self.target),
                "port_range": format_port_spec(self.ports),
                "total_open_ports": len(self.records),
                "scan_duration_seconds": round(duration, 3),
                "batches_completed": self.batches_completed,
                "batches_total": self.batch_total,
            }

    def snapshot(self) -> dict:
        """Bản chụp trạng thái để trả về qua API JSON."""
        with self._lock:
            payload = {
                "id": self.id,
                "target": str(self.target),
                "ports": format_port_spec(self.ports),
                "status": self.status,
                "phase": self.phase,
                "message": self.message,
                # Giữ nguyên 'progress' cũ (tiến độ trong lô hiện tại) để không
                # làm hỏng giao diện đang dùng.
                "progress": {"done": self.done, "total": self.total},
                "batch": {
                    "index": self.batch_index,
                    "total": self.batch_total,
                    "completed": self.batches_completed,
                    "port_range": self.batch_port_range,
                    "ports_done": self.ports_done,
                    "ports_total": self.ports_total,
                },
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "params": {
                    "timeout": self.timeout,
                    "banner_timeout": self.banner_timeout,
                    "discovery_timeout": self.discovery_timeout,
                    "discovery_ports": format_port_spec(list(self.discovery_ports)),
                    "workers": self.workers,
                },
                "total_open_ports": len(self.records),
                "results": list(self.records),
                "errors": list(self.errors),
                "downloads": {
                    "json": f"/api/scan/{self.id}/download?format=json",
                    "csv": f"/api/scan/{self.id}/download?format=csv",
                },
            }
        # Sắp xếp ngoài lock để không giữ lock lâu khi có nhiều kết quả.
        payload["results"] = [
            asdict(record) for record in sort_records(payload["results"])
        ]
        return payload


def finish_job(job: ScanJob, status: str, message: str) -> None:
    """Chốt trạng thái cuối của lần quét."""
    job.mark_finished(status, message)


def run_scan(job: ScanJob) -> None:
    """Chạy quét trong thread nền, chia cổng thành từng lô.

    Tái sử dụng logic trong scanner.py: dò host sống cho CIDR đúng MỘT lần ở
    đầu, rồi với mỗi lô cổng thì quét lô đó trên tất cả host sống. Kết quả được
    gộp vào job ngay sau mỗi lô, nên API polling trả về được kết quả từng phần.
    """
    errors: list[str] = []
    batches = job.batches
    workers = job.workers

    try:
        targets = [str(job.target)]

        if isinstance(job.target, ipaddress.IPv4Network):
            hosts = [str(host) for host in job.target.hosts()]
            job.progress(
                f"Đang dò host sống trong {job.target} ({len(hosts)} host)...",
                0,
                len(hosts),
                "discovery",
            )

            def on_discovery(done: int, total: int, host: str, alive: bool) -> None:
                status = "sống" if alive else "không phản hồi"
                job.progress(f"[{done}/{total}] {host}: {status}", done, total, "discovery")

            targets = discover_hosts(
                hosts,
                ports=job.discovery_ports,
                timeout=job.discovery_timeout,
                workers=workers,
                on_progress=on_discovery,
                should_cancel=job.is_cancelled,
            )

            if job.is_cancelled():
                finish_job(job, "cancelled", "Đã hủy quét.")
                return
            if not targets:
                finish_job(
                    job,
                    "done",
                    "Không tìm thấy host nào phản hồi nên bỏ qua quét cổng.",
                )
                return

            # Kiểm tra thật giai đoạn quét cổng bằng số host sống thực tế. Đây là
            # phép so sánh độc lập của giai đoạn quét, không cộng lượt dò host.
            attempts = estimate_stage_attempts(len(targets), len(job.ports))
            if attempts > HARD_ATTEMPTS:
                finish_job(
                    job,
                    "error",
                    "Sau khi dò host sống: "
                    f"{len(targets)} host sống × {len(job.ports)} cổng = "
                    f"{format_attempts(attempts)} lượt, vượt trần cứng "
                    f"{format_attempts(HARD_ATTEMPTS)} ở "
                    f"{STAGE_LABELS[STAGE_SCAN]}. Dừng trước khi quét cổng.",
                )
                return
            if attempts > WARN_ATTEMPTS and not job.confirmed_large_scan:
                finish_job(
                    job,
                    "error",
                    "Sau khi dò host sống: "
                    f"{len(targets)} host sống × {len(job.ports)} cổng = "
                    f"{format_attempts(attempts)} lượt, vượt mốc "
                    f"{format_attempts(WARN_ATTEMPTS)} ở "
                    f"{STAGE_LABELS[STAGE_SCAN]}. Hãy chạy lại và xác nhận "
                    "quét lớn, hoặc giảm số cổng / thu nhỏ dải CIDR.",
                )
                return

        host_count = len(targets)
        completed_ports = 0

        for batch_index, batch_ports in enumerate(batches, start=1):
            if job.is_cancelled():
                finish_job(job, "cancelled", "Đã hủy quét.")
                return

            batch_size = len(batch_ports)
            job.update(
                batch_index=batch_index,
                batch_port_range=format_port_spec(batch_ports),
                phase="scanning",
            )

            for host_index, host in enumerate(targets, start=1):
                if job.is_cancelled():
                    finish_job(job, "cancelled", "Đã hủy quét.")
                    return

                job.progress(
                    f"[{host_index}/{host_count}] Đang quét {host} "
                    f"(lô {batch_index}/{len(batches)}, {batch_size} cổng)...",
                    0,
                    batch_size,
                    "scanning",
                )

                def on_port(
                    done: int,
                    total: int,
                    _host: str = host,
                    _host_index: int = host_index,
                ) -> None:
                    # Tiến độ trong lô hiện tại, quy đổi dần ra tiến độ cả job.
                    fraction = (
                        (_host_index - 1) + (done / total if total else 1.0)
                    ) / host_count
                    job.update(
                        message=(
                            f"[{_host_index}/{host_count}] {_host}: "
                            f"{done}/{total} cổng"
                        ),
                        done=done,
                        total=total,
                        phase="scanning",
                        ports_done=int(completed_ports + batch_size * fraction),
                    )

                open_ports, port_errors = scan_ports(
                    host,
                    batch_ports,
                    timeout=job.timeout,
                    workers=workers,
                    on_progress=on_port,
                    should_cancel=job.is_cancelled,
                )
                errors.extend(
                    f"{host}:{port} {message}" for port, message in port_errors
                )

                # Banner chỉ đọc cho cổng đã mở nên rất nhanh, kể cả khi vừa hủy.
                banners = grab_banners(
                    host,
                    open_ports,
                    timeout=job.banner_timeout,
                    workers=workers,
                )
                job.add_records(
                    build_records(host, open_ports, banners, current_timestamp())
                )
                job.update(errors=list(errors))

                if job.is_cancelled():
                    finish_job(job, "cancelled", "Đã hủy quét.")
                    return

            completed_ports += batch_size
            job.update(
                ports_done=completed_ports,
                batches_completed=batch_index,
            )

        finish_job(
            job,
            "done",
            f"Hoàn tất: {len(job.records_snapshot())} cổng mở.",
        )
    except Exception as exc:  # noqa: BLE001 - không để lộ traceback ra trình duyệt
        job.update(errors=list(errors))
        finish_job(job, "error", f"Lỗi khi quét: {exc}")


class ScanManager:
    """Giữ các lần quét và bảo đảm mỗi lúc chỉ có một lần quét chạy."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, ScanJob] = {}
        self._order: list[str] = []

    def start(
        self,
        target: ipaddress.IPv4Address | ipaddress.IPv4Network,
        ports: list[int],
        workers: int = DEFAULT_WORKERS,
        timeout: float = DEFAULT_SCAN_TIMEOUT,
        banner_timeout: float = DEFAULT_BANNER_TIMEOUT,
        discovery_timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
        discovery_ports: tuple[int, ...] = DISCOVERY_PORTS,
        confirmed_large_scan: bool = False,
    ) -> ScanJob:
        with self._lock:
            for existing in self._jobs.values():
                if existing.status == "running":
                    raise ApiError(
                        409,
                        "Đang có một lần quét chạy. Hãy đợi hoặc hủy lần quét đó trước.",
                    )
            job = ScanJob(
                target,
                ports,
                workers=workers,
                timeout=timeout,
                banner_timeout=banner_timeout,
                discovery_timeout=discovery_timeout,
                discovery_ports=discovery_ports,
                confirmed_large_scan=confirmed_large_scan,
            )
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > KEEP_JOBS:
                stale = self._order.pop(0)
                self._jobs.pop(stale, None)

        thread = threading.Thread(
            target=run_scan,
            args=(job,),
            name=f"scan-{job.id[:8]}",
            daemon=True,
        )
        thread.start()
        return job

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def running_job(self) -> ScanJob | None:
        """Job đang chạy, nếu có (dùng cho kiểm thử và chẩn đoán)."""
        with self._lock:
            for job in self._jobs.values():
                if job.status == "running":
                    return job
        return None

    def cancel(self, job_id: str) -> ScanJob:
        job = self.get(job_id)
        if job is None:
            raise ApiError(404, "Không tìm thấy lần quét này.")
        if job.status != "running":
            raise ApiError(409, "Lần quét này đã kết thúc nên không thể hủy.")
        job.cancel_event.set()
        job.update(message="Đang hủy quét...")
        return job


def _parse_json_object(raw_body: bytes) -> dict:
    """Đọc body thành đối tượng JSON, báo lỗi rõ ràng nếu sai."""
    if not raw_body:
        raise ApiError(400, "Thiếu nội dung JSON trong yêu cầu.")
    try:
        data = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApiError(400, "JSON không hợp lệ.") from exc
    if not isinstance(data, dict):
        raise ApiError(400, "Nội dung JSON phải là một đối tượng.")
    return data


def _optional_bool(data: dict, key: str, default: bool = False) -> bool:
    """Đọc một cờ boolean từ JSON."""
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ApiError(400, f"Trường '{key}' phải là true hoặc false.")
    return value


def _optional_timeout(
    data: dict,
    key: str,
    default: float,
) -> float:
    """Đọc một tham số thời gian từ JSON và kiểm tra khoảng hợp lệ."""
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ApiError(400, f"Trường '{key}' phải là một số.")
    number = float(value)
    if not math.isfinite(number) or not MIN_TIMEOUT <= number <= MAX_TIMEOUT:
        raise ApiError(
            400,
            f"Trường '{key}' phải trong khoảng {MIN_TIMEOUT}-{MAX_TIMEOUT} giây.",
        )
    return number


def _optional_workers(data: dict) -> int:
    """Đọc số luồng từ JSON và kiểm tra giới hạn phía server."""
    value = data.get("workers", DEFAULT_WORKERS)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ApiError(400, "Trường 'workers' phải là số nguyên.")
    if not 1 <= value <= MAX_WORKERS:
        raise ApiError(400, f"Trường 'workers' phải trong khoảng 1-{MAX_WORKERS}.")
    return value


def _optional_discovery_ports(data: dict) -> tuple[int, ...]:
    """Đọc danh sách cổng dò host sống từ JSON."""
    value = data.get("discovery_ports")
    if value is None:
        return DISCOVERY_PORTS
    if not isinstance(value, str) or not value.strip():
        raise ApiError(
            400,
            "Trường 'discovery_ports' phải là chuỗi, ví dụ 22,80,443.",
        )
    try:
        ports = parse_ports(value.strip())
    except argparse.ArgumentTypeError as exc:
        raise ApiError(400, f"Trường 'discovery_ports': {exc}") from exc
    if not ports:
        raise ApiError(400, "Trường 'discovery_ports' không được rỗng.")
    if len(ports) > MAX_DISCOVERY_PORTS:
        raise ApiError(
            400,
            f"Trường 'discovery_ports' tối đa {MAX_DISCOVERY_PORTS} cổng "
            f"(yêu cầu {len(ports)}).",
        )
    return tuple(ports)


class ScanRequestHandler(BaseHTTPRequestHandler):
    """Xử lý request HTTP cho giao diện web cục bộ."""

    server_version = "PortScannerWeb/1.0"
    sys_version = ""

    # ------------------------------------------------------------------
    # Tiện ích
    # ------------------------------------------------------------------

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("[web] %s %s\n" % (self.client_address[0], fmt % args))

    def _host_ok(self) -> bool:
        """Chỉ chấp nhận Host của chính server (chống DNS rebinding)."""
        return self.headers.get("Host", "") in self.server.allowed_hosts

    def _origin_ok(self) -> bool:
        """Origin, nếu có, phải trùng địa chỉ server (chống CSRF)."""
        origin = self.headers.get("Origin")
        if not origin:
            # curl hoặc script không gửi Origin; token vẫn bắt buộc.
            return True
        return origin in self.server.allowed_origins

    def _token_ok(self) -> bool:
        provided = self.headers.get(TOKEN_HEADER, "")
        try:
            return secrets.compare_digest(provided, self.server.token)
        except TypeError:
            return False

    def _send_body(
        self,
        status: int,
        content_type: str,
        body: bytes,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(
        self,
        status: int,
        payload: dict,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_body(
            status,
            "application/json; charset=utf-8",
            body,
            extra_headers,
        )

    def _fail(self, status: int, message: str) -> None:
        try:
            self._send_json(status, {"error": message})
        except OSError:
            # Client đóng kết nối sớm; không cần làm gì thêm.
            pass

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError as exc:
            raise ApiError(400, "Header Content-Length không hợp lệ.") from exc
        if length < 0:
            raise ApiError(400, "Header Content-Length không hợp lệ.")
        if length > MAX_BODY_BYTES:
            raise ApiError(
                413,
                f"Nội dung yêu cầu quá lớn (tối đa {MAX_BODY_BYTES} byte).",
            )
        if length == 0:
            return b""
        return self.rfile.read(length)

    # ------------------------------------------------------------------
    # Điều phối
    # ------------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - tên do BaseHTTPRequestHandler quy định
        try:
            self._handle_get()
        except ApiError as exc:
            self._fail(exc.status, exc.message)
        except Exception:  # noqa: BLE001 - không để lộ traceback ra trình duyệt
            self._fail(500, "Lỗi máy chủ nội bộ.")

    def do_POST(self) -> None:  # noqa: N802 - tên do BaseHTTPRequestHandler quy định
        try:
            self._handle_post()
        except ApiError as exc:
            self._fail(exc.status, exc.message)
        except Exception:  # noqa: BLE001 - không để lộ traceback ra trình duyệt
            self._fail(500, "Lỗi máy chủ nội bộ.")

    def _handle_get(self) -> None:
        if not self._host_ok():
            raise ApiError(403, "Host header không hợp lệ.")

        parsed = urlparse(self.path)

        if parsed.path in ("/", "/index.html"):
            self._send_body(
                200,
                "text/html; charset=utf-8",
                self.server.index_html,
                extra_headers={
                    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer",
                },
            )
            return

        parts = [segment for segment in parsed.path.split("/") if segment]
        if len(parts) >= 3 and parts[0] == "api" and parts[1] == "scan":
            job = self.server.manager.get(parts[2])
            if job is None:
                raise ApiError(404, "Không tìm thấy lần quét này.")
            if len(parts) == 3:
                self._send_json(200, job.snapshot())
                return
            if len(parts) == 4 and parts[3] == "download":
                self._handle_download(job, parsed.query)
                return

        raise ApiError(404, "Không tìm thấy tài nguyên.")

    def _handle_download(self, job: ScanJob, query: str) -> None:
        # Kết quả chứa IP nội bộ nên vẫn yêu cầu token dù đây là GET.
        if not self._token_ok():
            raise ApiError(403, "Thiếu hoặc sai token.")

        report_format = (parse_qs(query).get("format") or ["json"])[0].lower()
        if report_format not in ("json", "csv"):
            raise ApiError(400, "Định dạng không hợp lệ; chỉ nhận json hoặc csv.")

        try:
            # Dùng lại đúng hàm định dạng mà CLI dùng để ghi báo cáo. Tải được
            # cả khi job đang chạy hoặc đã bị hủy: chỉ trả những kết quả đã có.
            text = render_report(
                report_format,
                job.records_for_report(),
                job.report_metadata(),
            )
        except ValueError as exc:
            raise ApiError(400, str(exc)) from exc

        content_type = (
            "application/json; charset=utf-8"
            if report_format == "json"
            else "text/csv; charset=utf-8"
        )
        filename = f"scan-{job.id[:8]}.{report_format}"
        self._send_body(
            200,
            content_type,
            text.encode("utf-8"),
            extra_headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    def _handle_post(self) -> None:
        # Đọc body trước để không bỏ sót dữ liệu khi trả lỗi.
        raw_body = self._read_body()

        if not self._host_ok():
            raise ApiError(403, "Host header không hợp lệ.")
        if not self._origin_ok():
            raise ApiError(403, "Origin không hợp lệ.")
        if not self._token_ok():
            raise ApiError(403, "Thiếu hoặc sai token.")

        parts = [segment for segment in urlparse(self.path).path.split("/") if segment]

        if parts == ["api", "scan"]:
            self._start_scan(raw_body)
            return
        if len(parts) == 4 and parts[:2] == ["api", "scan"] and parts[3] == "cancel":
            job = self.server.manager.cancel(parts[2])
            self._send_json(200, {"cancelled": True, "job": job.snapshot()})
            return

        raise ApiError(404, "Không tìm thấy tài nguyên.")

    def _start_scan(self, raw_body: bytes) -> None:
        data = _parse_json_object(raw_body)

        target_raw = data.get("target")
        ports_raw = data.get("ports")
        if not isinstance(target_raw, str) or not target_raw.strip():
            raise ApiError(400, "Thiếu trường 'target' (chuỗi IP hoặc CIDR).")
        if not isinstance(ports_raw, str) or not ports_raw.strip():
            raise ApiError(400, "Thiếu trường 'ports' (chuỗi dải cổng, ví dụ 1-1024).")

        # Kiểm tra phía server, không tin giao diện.
        try:
            target = parse_target(target_raw.strip())
        except argparse.ArgumentTypeError as exc:
            raise ApiError(400, str(exc)) from exc
        if not is_internal(target):
            raise ApiError(
                403,
                "Chỉ cho phép quét mục tiêu trong dải IP nội bộ "
                "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8).",
            )

        try:
            ports = parse_ports(ports_raw.strip())
        except argparse.ArgumentTypeError as exc:
            raise ApiError(400, str(exc)) from exc
        if not ports:
            raise ApiError(400, "Danh sách cổng rỗng.")
        if len(ports) > MAX_PORTS:
            raise ApiError(
                400,
                f"Số cổng tối đa là {MAX_PORTS} (yêu cầu {len(ports)}).",
            )

        # Các tham số nâng cao, luôn được kiểm tra lại phía server.
        workers = _optional_workers(data)
        timeout = _optional_timeout(data, "timeout", DEFAULT_SCAN_TIMEOUT)
        banner_timeout = _optional_timeout(
            data, "banner_timeout", DEFAULT_BANNER_TIMEOUT
        )
        discovery_timeout = _optional_timeout(
            data, "discovery_timeout", DEFAULT_DISCOVERY_TIMEOUT
        )
        discovery_ports = _optional_discovery_ports(data)
        confirmed = _optional_bool(data, "confirm")

        # Mỗi giai đoạn được đánh giá ĐỘC LẬP: không cộng lượt dò host với lượt
        # quét cổng để so với một trần chung.
        is_network = isinstance(target, ipaddress.IPv4Network)
        max_hosts = count_target_hosts(target)

        estimates: dict[str, dict] = {}
        if is_network:
            discovery_count = len(discovery_ports)
            discovery_seconds = estimate_stage_seconds(
                max_hosts, discovery_count, discovery_timeout, workers
            )
            estimates[STAGE_DISCOVERY] = {
                "stage": STAGE_DISCOVERY,
                "label": STAGE_LABELS[STAGE_DISCOVERY],
                "hosts": max_hosts,
                "ports": discovery_count,
                "attempts": estimate_stage_attempts(max_hosts, discovery_count),
                "seconds": round(discovery_seconds, 1),
                "duration": format_duration(discovery_seconds),
            }

        scan_seconds = estimate_stage_seconds(
            max_hosts, len(ports), timeout, workers
        )
        estimates[STAGE_SCAN] = {
            "stage": STAGE_SCAN,
            "label": STAGE_LABELS[STAGE_SCAN],
            "hosts": max_hosts,
            "ports": len(ports),
            "attempts": estimate_stage_attempts(max_hosts, len(ports)),
            "seconds": round(scan_seconds, 1),
            "duration": format_duration(scan_seconds),
        }

        # Trần cứng: giai đoạn nào vượt thì từ chối ngay và nêu rõ giai đoạn đó.
        for stage in (STAGE_DISCOVERY, STAGE_SCAN):
            info = estimates.get(stage)
            if info is None or info["attempts"] <= HARD_ATTEMPTS:
                continue
            raise ApiError(
                400,
                stage_limit_message(stage, info["hosts"], info["ports"]),
            )

        # Mốc cảnh báo: trả về bước xác nhận riêng, chỉ nêu các giai đoạn vượt
        # mốc. Giai đoạn vượt trần cứng đã bị từ chối ở trên nên không tới đây.
        over_warning = [
            info
            for info in estimates.values()
            if info["attempts"] > WARN_ATTEMPTS
        ]
        if over_warning and not confirmed:
            lines: list[str] = []
            for info in over_warning:
                lines.extend(
                    stage_warning_lines(
                        info["stage"], info["attempts"], info["seconds"]
                    )
                )
            self._send_json(
                202,
                {
                    "confirmation_required": True,
                    "reason": "large_scan",
                    "message": " ".join(lines),
                    "stages": [info["stage"] for info in over_warning],
                    "estimates": {
                        STAGE_DISCOVERY: estimates.get(STAGE_DISCOVERY),
                        STAGE_SCAN: estimates[STAGE_SCAN],
                    },
                    "warn_threshold": WARN_ATTEMPTS,
                    "hard_threshold": HARD_ATTEMPTS,
                },
            )
            return

        job = self.server.manager.start(
            target,
            ports,
            workers=workers,
            timeout=timeout,
            banner_timeout=banner_timeout,
            discovery_timeout=discovery_timeout,
            discovery_ports=discovery_ports,
            confirmed_large_scan=confirmed,
        )
        self._send_json(202, job.snapshot())


class WebServer(ThreadingHTTPServer):
    """HTTP server chỉ lắng nghe trên loopback."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[ScanRequestHandler],
        token: str,
        manager: ScanManager,
        index_html: bytes,
    ) -> None:
        super().__init__(address, handler)
        self.token = token
        self.manager = manager
        self.index_html = index_html
        # Host/Origin hợp lệ được suy ra từ cổng thật sau khi bind.
        self.allowed_hosts = {
            f"127.0.0.1:{self.server_port}",
            f"localhost:{self.server_port}",
        }
        self.allowed_origins = {
            f"http://127.0.0.1:{self.server_port}",
            f"http://localhost:{self.server_port}",
        }


def load_index_html(token: str) -> bytes:
    """Đọc index.html, nhúng token phiên và hai mốc giới hạn vào trang."""
    try:
        template = INDEX_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"Không đọc được {INDEX_FILE}: {exc}") from exc

    replacements = {
        TOKEN_PLACEHOLDER: token,
        WARN_PLACEHOLDER: str(WARN_ATTEMPTS),
        HARD_PLACEHOLDER: str(HARD_ATTEMPTS),
    }
    for placeholder, value in replacements.items():
        if placeholder not in template:
            raise SystemExit(f"{INDEX_FILE} thiếu chỗ đánh dấu {placeholder}.")
        template = template.replace(placeholder, value)
    return template.encode("utf-8")


def port_number(value: str) -> int:
    """Kiểm tra --port là số nguyên trong khoảng hợp lệ."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("cổng phải là số nguyên") from exc
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError("cổng phải trong khoảng 1-65535")
    return number


def build_parser() -> argparse.ArgumentParser:
    """Tạo bộ phân tích tham số dòng lệnh.

    Cố ý không có tham số đổi địa chỉ bind: server luôn chỉ nghe trên 127.0.0.1.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Web server cục bộ hiển thị kết quả quét cổng. "
            "Chỉ lắng nghe trên 127.0.0.1."
        ),
    )
    parser.add_argument(
        "--port",
        type=port_number,
        default=DEFAULT_PORT,
        metavar="PORT",
        help=f"cổng lắng nghe trên 127.0.0.1 (mặc định: {DEFAULT_PORT})",
    )
    return parser


def main() -> int:
    """Khởi động web server và phục vụ cho tới khi bị Ctrl+C."""
    configure_output_encoding()
    args = build_parser().parse_args()

    token = secrets.token_urlsafe(32)
    index_html = load_index_html(token)
    manager = ScanManager()

    try:
        server = WebServer(
            (BIND_HOST, args.port),
            ScanRequestHandler,
            token,
            manager,
            index_html,
        )
    except OSError as exc:
        print(f"Không mở được cổng {args.port} trên {BIND_HOST}: {exc}")
        return 1

    url = f"http://{BIND_HOST}:{server.server_port}/"
    print(f"Web UI: {url}")
    print(f"Chỉ lắng nghe trên {BIND_HOST}:{server.server_port} (không vào được từ mạng LAN).")
    print(
        f"Giới hạn: tối đa {MAX_PORTS} cổng mỗi lần quét, chia thành các lô "
        f"{BATCH_SIZE} cổng; giai đoạn dò host và giai đoạn quét cổng được đánh "
        f"giá độc lập: cảnh báo khi vượt {format_attempts(WARN_ATTEMPTS)} lượt "
        f"và từ chối khi vượt {format_attempts(HARD_ATTEMPTS)} lượt mỗi giai "
        "đoạn; chỉ mục tiêu trong dải nội bộ."
    )
    print("Nhấn Ctrl+C để dừng.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nĐang dừng web server...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
