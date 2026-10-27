"""Web server cục bộ hiển thị kết quả quét cổng.

Hai giai đoạn là hai loại job độc lập, không job nào tự chuyển từ giai đoạn này
sang giai đoạn kia:

- job ``discover`` dò host sống trong một dải CIDR và trả về danh sách host;
- job ``scan`` quét cổng trên một danh sách host do client chọn.

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
    CONCURRENCY_WARN,
    DEFAULT_CONCURRENCY,
    HARD_ATTEMPTS,
    MAX_CONCURRENCY,
    STAGE_DISCOVERY,
    STAGE_LABELS,
    STAGE_SCAN,
    WARN_ATTEMPTS,
    build_records,
    build_report_metadata,
    configure_output_encoding,
    concurrency_warning_lines,
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
from scanner import DISCOVERY_PORTS, discover_hosts, scan_targets


# Bắt buộc: chỉ lắng nghe trên loopback, không bao giờ bind ra ngoài.
BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8000

# Token chống CSRF: sinh mỗi lần khởi động và bắt buộc với mọi request POST.
TOKEN_HEADER = "X-Scan-Token"

# Hai loại job độc lập.
KIND_DISCOVER = "discover"
KIND_SCAN = "scan"

# Giới hạn phía server, không tin giá trị do trình duyệt gửi lên.
MAX_PORTS = 65535
MAX_DISCOVERY_PORTS = 64
# Giới hạn body đủ lớn cho danh sách host của một lần dò /18 (tối đa 16382 host,
# khoảng 300 KB JSON); vẫn chặn mọi payload lớn hơn.
MAX_BODY_BYTES = 1_048_576
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


def sort_records(records: list[ScanRecord]) -> list[ScanRecord]:
    """Sắp xếp kết quả theo địa chỉ IP (so sánh số) rồi theo cổng."""

    def key(record: ScanRecord) -> tuple[int, int]:
        try:
            return (int(ipaddress.IPv4Address(record.host)), record.port)
        except ValueError:
            # Không phải IPv4 (không xảy ra với dữ liệu hiện tại): xếp cuối.
            return (1 << 32, record.port)

    return sorted(records, key=key)


class BaseJob:
    """Vòng đời chung của một job chạy ở thread nền."""

    kind = ""

    def __init__(self, confirmed_large_scan: bool = False) -> None:
        self.id = uuid.uuid4().hex
        self.confirmed_large_scan = confirmed_large_scan
        self.status = "running"
        self.phase = "starting"
        self.message = "Đang khởi động..."
        self.errors: list[str] = []
        self.started_at = current_timestamp()
        self.finished_at: str | None = None
        self.cancel_event = threading.Event()
        self._lock = threading.Lock()
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

    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def mark_finished(self, status: str, message: str) -> None:
        """Chốt trạng thái cuối của job."""
        with self._lock:
            self.status = status
            self.message = message
            self.finished_at = current_timestamp()
            self._duration = time.perf_counter() - self._started_monotonic

    def _duration_seconds(self) -> float:
        duration = self._duration
        if duration is None:
            duration = time.perf_counter() - self._started_monotonic
        return duration

    def _base_snapshot(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "status": self.status,
            "phase": self.phase,
            "message": self.message,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self._duration_seconds(), 3),
            "errors": list(self.errors),
        }

    def snapshot(self) -> dict:
        raise NotImplementedError


class DiscoverJob(BaseJob):
    """Một lần dò host sống trong một dải CIDR."""

    kind = KIND_DISCOVER

    def __init__(
        self,
        cidr: ipaddress.IPv4Network,
        discovery_ports: tuple[int, ...] = DISCOVERY_PORTS,
        discovery_timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
        concurrency: int = DEFAULT_CONCURRENCY,
        confirmed_large_scan: bool = False,
    ) -> None:
        super().__init__(confirmed_large_scan=confirmed_large_scan)
        self.cidr = cidr
        self.discovery_ports = tuple(discovery_ports)
        self.discovery_timeout = discovery_timeout
        self.concurrency = concurrency
        self.live_hosts: list[str] = []
        self.hosts_total = count_target_hosts(cidr)
        self.done = 0
        self.total = self.hosts_total
        self.warnings = concurrency_warning_lines(concurrency)

    def set_live_hosts(self, hosts: list[str]) -> None:
        with self._lock:
            self.live_hosts = list(hosts)

    def live_hosts_snapshot(self) -> list[str]:
        with self._lock:
            return list(self.live_hosts)

    def snapshot(self) -> dict:
        with self._lock:
            payload = self._base_snapshot()
            payload.update(
                {
                    "cidr": str(self.cidr),
                    "hosts_total": self.hosts_total,
                    "live_hosts": list(self.live_hosts),
                    "total_live_hosts": len(self.live_hosts),
                    "progress": {"done": self.done, "total": self.total},
                    "warnings": list(self.warnings),
                    "params": {
                        "discovery_ports": format_port_spec(
                            list(self.discovery_ports)
                        ),
                        "discovery_timeout": self.discovery_timeout,
                        "concurrency": self.concurrency,
                    },
                }
            )
            return payload


class ScanJob(BaseJob):
    """Một lần quét cổng trên danh sách host đã biết."""

    kind = KIND_SCAN

    def __init__(
        self,
        hosts: list[ipaddress.IPv4Address],
        ports: list[int],
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: float = DEFAULT_SCAN_TIMEOUT,
        banner_timeout: float = DEFAULT_BANNER_TIMEOUT,
        confirmed_large_scan: bool = False,
    ) -> None:
        super().__init__(confirmed_large_scan=confirmed_large_scan)
        self.hosts = list(hosts)
        self.ports = list(ports)
        self.concurrency = concurrency
        self.timeout = timeout
        self.banner_timeout = banner_timeout
        self.warnings = concurrency_warning_lines(concurrency)
        self.done = 0
        # Tổng số lượt quét của job: số host × số cổng, không chia lô.
        self.total = len(self.hosts) * len(self.ports)
        self.records: list[ScanRecord] = []

    def add_records(self, records: list[ScanRecord]) -> None:
        with self._lock:
            self.records.extend(records)

    def records_snapshot(self) -> list[ScanRecord]:
        with self._lock:
            return list(self.records)

    def records_for_report(self) -> list[ScanRecord]:
        """Kết quả đã sắp xếp, dùng cho cả snapshot API lẫn file tải về."""
        return sort_records(self.records_snapshot())

    def target_label(self) -> str:
        """Nhãn mục tiêu dùng cho báo cáo và giao diện."""
        if len(self.hosts) == 1:
            return str(self.hosts[0])
        return f"{len(self.hosts)} host"

    def report_metadata(self) -> dict:
        """Metadata của báo cáo, tính tại thời điểm gọi.

        Nhờ vậy vẫn tải được báo cáo khi job đang chạy hoặc đã bị hủy, và kết
        quả luôn đúng với thời điểm tải. Dùng chung hàm với CLI để định dạng báo
        cáo chỉ có một nguồn.
        """
        with self._lock:
            return build_report_metadata(
                list(self.hosts),
                self.ports,
                list(self.records),
                self._duration_seconds(),
            )

    def snapshot(self) -> dict:
        """Bản chụp trạng thái để trả về qua API JSON."""
        with self._lock:
            payload = self._base_snapshot()
            payload.update(
                {
                    "target": self.target_label(),
                    "hosts": [str(host) for host in self.hosts],
                    "host_count": len(self.hosts),
                    "ports": format_port_spec(self.ports),
                    "progress": {
                        "done": self.done,
                        "total": self.total,
                        "percent": (
                            round(100 * self.done / self.total, 1)
                            if self.total
                            else 0.0
                        ),
                    },
                    "warnings": list(self.warnings),
                    "params": {
                        "timeout": self.timeout,
                        "banner_timeout": self.banner_timeout,
                        "concurrency": self.concurrency,
                    },
                    "total_open_ports": len(self.records),
                    "results": list(self.records),
                    "downloads": {
                        "json": f"/api/scan/{self.id}/download?format=json",
                        "csv": f"/api/scan/{self.id}/download?format=csv",
                    },
                }
            )
        # Sắp xếp ngoài lock để không giữ lock lâu khi có nhiều kết quả.
        payload["results"] = [
            asdict(record) for record in sort_records(payload["results"])
        ]
        return payload


def finish_job(job: BaseJob, status: str, message: str) -> None:
    """Chốt trạng thái cuối của job."""
    job.mark_finished(status, message)


def run_discover(job: DiscoverJob) -> None:
    """Chạy giai đoạn dò host sống trong thread nền; không quét cổng."""
    hosts = [str(host) for host in job.cidr.hosts()]

    def on_progress(done: int, total: int, host: str, alive: bool) -> None:
        status = "sống" if alive else "không phản hồi"
        job.progress(f"[{done}/{total}] {host}: {status}", done, total, "discovery")

    try:
        live_hosts = discover_hosts(
            hosts,
            ports=job.discovery_ports,
            timeout=job.discovery_timeout,
            workers=job.concurrency,
            on_progress=on_progress,
            should_cancel=job.is_cancelled,
        )

        if job.is_cancelled():
            job.set_live_hosts(live_hosts)
            finish_job(job, "cancelled", "Đã hủy dò host.")
            return

        job.set_live_hosts(live_hosts)
        finish_job(
            job,
            "done",
            f"Hoàn tất: {len(live_hosts)}/{len(hosts)} host sống.",
        )
    except Exception as exc:  # noqa: BLE001 - không để lộ traceback ra trình duyệt
        finish_job(job, "error", f"Lỗi khi dò host: {exc}")


def run_scan(job: ScanJob) -> None:
    """Chạy quét cổng trên danh sách host đã biết, trả kết quả ngay khi có.

    Không chia lô: mọi cặp (host, cổng) vào cùng một lượt quét, cổng nào xong
    trước thì ghi vào job ngay, nên giao diện thấy kết quả mà không phải chờ
    hết một nhóm. Không dò host sống ở đây: danh sách host do client chọn từ
    kết quả của một job discover trước đó (hoặc một IP đơn).
    """
    targets = [str(host) for host in job.hosts]
    total = job.total

    def on_result(host: str, port: int, banner: str | None) -> None:
        banners = {port: banner} if banner else {}
        job.add_records(
            build_records(host, [port], banners, current_timestamp())
        )

    def on_progress(done: int, _total: int) -> None:
        job.update(
            done=done,
            phase="scanning",
            message=(
                f"Đã quét {done}/{total} cổng, "
                f"{len(job.records_snapshot())} cổng mở."
            ),
        )

    try:
        _, errors = scan_targets(
            ((host, port) for host in targets for port in job.ports),
            total=total,
            workers=job.concurrency,
            timeout=job.timeout,
            banner_timeout=job.banner_timeout,
            on_result=on_result,
            on_progress=on_progress,
            should_cancel=job.is_cancelled,
        )
        for host, port, message in errors:
            job.errors.append(f"{host}:{port} {message}")

        open_count = len(job.records_snapshot())
        if job.is_cancelled():
            finish_job(
                job,
                "cancelled",
                f"Đã hủy quét: giữ lại {open_count} cổng mở đã quét.",
            )
            return

        finish_job(job, "done", f"Hoàn tất: {open_count} cổng mở.")
    except Exception as exc:  # noqa: BLE001 - không để lộ traceback ra trình duyệt
        finish_job(job, "error", f"Lỗi khi quét: {exc}")


class JobManager:
    """Giữ các job; mỗi loại (discover/scan) chỉ cho một job chạy tại một thời điểm.

    Hai loại độc lập nên có thể chạy đồng thời một job discover và một job scan.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, BaseJob] = {}
        self._order: list[str] = []

    def _running_of_kind(self, kind: str) -> BaseJob | None:
        for job in self._jobs.values():
            if job.kind == kind and job.status == "running":
                return job
        return None

    def _conflict_message(self, kind: str) -> str:
        if kind == KIND_DISCOVER:
            return (
                "Đang có một lần dò host chạy. Hãy đợi hoặc hủy lần dò đó trước."
            )
        return "Đang có một lần quét chạy. Hãy đợi hoặc hủy lần quét đó trước."

    def _register(self, job: BaseJob) -> None:
        self._jobs[job.id] = job
        self._order.append(job.id)
        while len(self._order) > KEEP_JOBS:
            stale = self._order.pop(0)
            stale_job = self._jobs.get(stale)
            if stale_job is not None and stale_job.status == "running":
                # Không bỏ job đang chạy; đẩy id về cuối hàng đợi.
                self._order.append(stale)
                break
            self._jobs.pop(stale, None)

    def start_discover(
        self,
        cidr: ipaddress.IPv4Network,
        discovery_ports: tuple[int, ...] = DISCOVERY_PORTS,
        discovery_timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
        concurrency: int = DEFAULT_CONCURRENCY,
        confirmed_large_scan: bool = False,
    ) -> DiscoverJob:
        with self._lock:
            if self._running_of_kind(KIND_DISCOVER) is not None:
                raise ApiError(409, self._conflict_message(KIND_DISCOVER))
            job = DiscoverJob(
                cidr,
                discovery_ports=discovery_ports,
                discovery_timeout=discovery_timeout,
                concurrency=concurrency,
                confirmed_large_scan=confirmed_large_scan,
            )
            self._register(job)

        thread = threading.Thread(
            target=run_discover,
            args=(job,),
            name=f"discover-{job.id[:8]}",
            daemon=True,
        )
        thread.start()
        return job

    def start_scan(
        self,
        hosts: list[ipaddress.IPv4Address],
        ports: list[int],
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: float = DEFAULT_SCAN_TIMEOUT,
        banner_timeout: float = DEFAULT_BANNER_TIMEOUT,
        confirmed_large_scan: bool = False,
    ) -> ScanJob:
        with self._lock:
            if self._running_of_kind(KIND_SCAN) is not None:
                raise ApiError(409, self._conflict_message(KIND_SCAN))
            job = ScanJob(
                hosts,
                ports,
                concurrency=concurrency,
                timeout=timeout,
                banner_timeout=banner_timeout,
                confirmed_large_scan=confirmed_large_scan,
            )
            self._register(job)

        thread = threading.Thread(
            target=run_scan,
            args=(job,),
            name=f"scan-{job.id[:8]}",
            daemon=True,
        )
        thread.start()
        return job

    def get(self, job_id: str) -> BaseJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def require(self, job_id: str, kind: str) -> BaseJob:
        """Lấy job theo id và đúng loại, nếu không thì 404."""
        job = self.get(job_id)
        if job is None or job.kind != kind:
            if kind == KIND_DISCOVER:
                raise ApiError(404, "Không tìm thấy lần dò host này.")
            raise ApiError(404, "Không tìm thấy lần quét này.")
        return job

    def running_job(self, kind: str | None = None) -> BaseJob | None:
        """Job đang chạy theo loại (hoặc bất kỳ), dùng cho kiểm thử/chẩn đoán."""
        with self._lock:
            if kind is None:
                for job in self._jobs.values():
                    if job.status == "running":
                        return job
                return None
            return self._running_of_kind(kind)

    def cancel(self, job_id: str, kind: str) -> BaseJob:
        job = self.require(job_id, kind)
        if job.status != "running":
            if kind == KIND_DISCOVER:
                raise ApiError(409, "Lần dò host này đã kết thúc nên không thể hủy.")
            raise ApiError(409, "Lần quét này đã kết thúc nên không thể hủy.")
        job.cancel_event.set()
        job.update(message="Đang hủy...")
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


def _optional_concurrency(data: dict) -> int:
    """Đọc số luồng (concurrency) từ JSON và kiểm tra giới hạn phía server."""
    value = data.get("concurrency", DEFAULT_CONCURRENCY)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ApiError(400, "Trường 'concurrency' phải là số nguyên.")
    if not 1 <= value <= MAX_CONCURRENCY:
        raise ApiError(
            400,
            "Trường 'concurrency' phải trong khoảng "
            f"1-{format_attempts(MAX_CONCURRENCY)}.",
        )
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


def _stage_estimate(
    stage: str,
    hosts: int,
    ports_count: int,
    seconds: float,
) -> dict:
    """Ước tính của một giai đoạn, dùng cho payload xác nhận quét lớn."""
    return {
        "stage": stage,
        "label": STAGE_LABELS[stage],
        "hosts": hosts,
        "ports": ports_count,
        "attempts": estimate_stage_attempts(hosts, ports_count),
        "seconds": round(seconds, 1),
        "duration": format_duration(seconds),
    }


def _confirmation_payload(info: dict) -> dict:
    """Payload 202 khi một giai đoạn vượt mốc cảnh báo."""
    return {
        "confirmation_required": True,
        "reason": "large_scan",
        "message": " ".join(
            stage_warning_lines(info["stage"], info["attempts"], info["seconds"])
        ),
        "stages": [info["stage"]],
        "estimates": {
            STAGE_DISCOVERY: (
                info if info["stage"] == STAGE_DISCOVERY else None
            ),
            STAGE_SCAN: info if info["stage"] == STAGE_SCAN else None,
        },
        "warn_threshold": WARN_ATTEMPTS,
        "hard_threshold": HARD_ATTEMPTS,
    }


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
        if len(parts) >= 3 and parts[0] == "api":
            if parts[1] == KIND_DISCOVER:
                job = self.server.manager.require(parts[2], KIND_DISCOVER)
                if len(parts) == 3:
                    self._send_json(200, job.snapshot())
                    return
            elif parts[1] == KIND_SCAN:
                job = self.server.manager.require(parts[2], KIND_SCAN)
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

        if parts == ["api", KIND_DISCOVER]:
            self._start_discover(raw_body)
            return
        if parts == ["api", KIND_SCAN]:
            self._start_scan(raw_body)
            return

        if len(parts) == 4 and parts[0] == "api" and parts[3] == "cancel":
            if parts[1] == KIND_DISCOVER:
                job = self.server.manager.cancel(parts[2], KIND_DISCOVER)
                self._send_json(200, {"cancelled": True, "job": job.snapshot()})
                return
            if parts[1] == KIND_SCAN:
                job = self.server.manager.cancel(parts[2], KIND_SCAN)
                self._send_json(200, {"cancelled": True, "job": job.snapshot()})
                return

        raise ApiError(404, "Không tìm thấy tài nguyên.")

    def _start_discover(self, raw_body: bytes) -> None:
        data = _parse_json_object(raw_body)

        cidr_raw = data.get("cidr")
        if not isinstance(cidr_raw, str) or not cidr_raw.strip():
            raise ApiError(
                400,
                "Thiếu trường 'cidr' (chuỗi CIDR, ví dụ \"192.168.1.0/24\").",
            )

        try:
            network = parse_target(cidr_raw.strip())
        except argparse.ArgumentTypeError as exc:
            raise ApiError(400, str(exc)) from exc
        if not isinstance(network, ipaddress.IPv4Network):
            raise ApiError(
                400,
                "Trường 'cidr' phải là một dải CIDR, không nhận một IP đơn; "
                "quét một IP thì gọi /api/scan với hosts.",
            )
        if not is_internal(network):
            raise ApiError(
                403,
                "Chỉ cho phép dò host trong dải IP nội bộ "
                "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8).",
            )

        discovery_ports = _optional_discovery_ports(data)
        discovery_timeout = _optional_timeout(
            data, "discovery_timeout", DEFAULT_DISCOVERY_TIMEOUT
        )
        concurrency = _optional_concurrency(data)
        confirmed = _optional_bool(data, "confirm")

        max_hosts = count_target_hosts(network)
        attempts = estimate_stage_attempts(max_hosts, len(discovery_ports))
        seconds = estimate_stage_seconds(
            max_hosts, len(discovery_ports), discovery_timeout, concurrency
        )

        if attempts > HARD_ATTEMPTS:
            raise ApiError(
                400,
                stage_limit_message(
                    STAGE_DISCOVERY, max_hosts, len(discovery_ports)
                ),
            )

        if attempts > WARN_ATTEMPTS and not confirmed:
            info = _stage_estimate(
                STAGE_DISCOVERY, max_hosts, len(discovery_ports), seconds
            )
            self._send_json(202, _confirmation_payload(info))
            return

        job = self.server.manager.start_discover(
            network,
            discovery_ports=discovery_ports,
            discovery_timeout=discovery_timeout,
            concurrency=concurrency,
            confirmed_large_scan=confirmed,
        )
        self._send_json(202, job.snapshot())

    def _start_scan(self, raw_body: bytes) -> None:
        data = _parse_json_object(raw_body)

        if data.get("target") is not None or data.get("cidr") is not None:
            raise ApiError(
                400,
                "POST /api/scan chỉ nhận 'hosts' (danh sách IPv4). Muốn quét "
                "theo CIDR, hãy gọi /api/discover trước rồi dùng danh sách "
                "live_hosts trả về.",
            )

        hosts_raw = data.get("hosts")
        if not isinstance(hosts_raw, list):
            raise ApiError(
                400,
                "Thiếu trường 'hosts' (danh sách IPv4, ví dụ [\"127.0.0.1\"]).",
            )
        if not hosts_raw:
            raise ApiError(400, "Trường 'hosts' không được rỗng.")

        hosts: list[ipaddress.IPv4Address] = []
        for entry in hosts_raw:
            if not isinstance(entry, str):
                raise ApiError(
                    400, "Mỗi phần tử trong 'hosts' phải là chuỗi IPv4."
                )
            text = entry.strip()
            if "/" in text:
                raise ApiError(
                    400,
                    "Trường 'hosts' chỉ nhận địa chỉ IPv4, không nhận CIDR; "
                    "hãy gọi /api/discover trước.",
                )
            try:
                host = ipaddress.ip_address(text)
            except ValueError as exc:
                raise ApiError(
                    400, f"Địa chỉ trong 'hosts' không hợp lệ: {text!r}."
                ) from exc
            if host.version != 4:
                raise ApiError(400, "Hiện chỉ hỗ trợ địa chỉ IPv4.")
            if not is_internal(host):
                raise ApiError(
                    403,
                    f"Host ngoài dải nội bộ bị từ chối: {host}. Chỉ cho phép "
                    "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8.",
                )
            hosts.append(host)
        hosts = list(dict.fromkeys(hosts))

        ports_raw = data.get("ports")
        if not isinstance(ports_raw, str) or not ports_raw.strip():
            raise ApiError(
                400, "Thiếu trường 'ports' (chuỗi dải cổng, ví dụ 1-1024)."
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
        concurrency = _optional_concurrency(data)
        timeout = _optional_timeout(data, "timeout", DEFAULT_SCAN_TIMEOUT)
        banner_timeout = _optional_timeout(
            data, "banner_timeout", DEFAULT_BANNER_TIMEOUT
        )
        confirmed = _optional_bool(data, "confirm")

        # Giới hạn của giai đoạn quét dùng SỐ HOST THẬT trong danh sách.
        attempts = estimate_stage_attempts(len(hosts), len(ports))
        seconds = estimate_stage_seconds(
            len(hosts), len(ports), timeout, concurrency
        )

        if attempts > HARD_ATTEMPTS:
            raise ApiError(
                400, stage_limit_message(STAGE_SCAN, len(hosts), len(ports))
            )

        if attempts > WARN_ATTEMPTS and not confirmed:
            info = _stage_estimate(STAGE_SCAN, len(hosts), len(ports), seconds)
            self._send_json(202, _confirmation_payload(info))
            return

        job = self.server.manager.start_scan(
            hosts,
            ports,
            concurrency=concurrency,
            timeout=timeout,
            banner_timeout=banner_timeout,
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
        manager: JobManager,
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
    manager = JobManager()

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
        f"Giới hạn: tối đa {MAX_PORTS} cổng mỗi lần quét, tối đa "
        f"{format_attempts(MAX_CONCURRENCY)} luồng mỗi job (cảnh báo trên "
        f"{format_attempts(CONCURRENCY_WARN)} luồng); job discover và job scan "
        "độc lập, mỗi loại chỉ một job tại một thời điểm; cảnh báo khi vượt "
        f"{format_attempts(WARN_ATTEMPTS)} lượt và từ chối khi vượt "
        f"{format_attempts(HARD_ATTEMPTS)} lượt mỗi giai đoạn; chỉ mục tiêu "
        "trong dải nội bộ."
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
