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
    build_records,
    configure_output_encoding,
    current_timestamp,
    format_port_spec,
    is_internal,
    parse_ports,
    parse_target,
)
from report import ScanRecord, render_report
from scanner import DISCOVERY_PORTS, discover_hosts, grab_banners, scan_ports


# Bắt buộc: chỉ lắng nghe trên loopback, không bao giờ bind ra ngoài.
BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8000

# Token chống CSRF: sinh mỗi lần khởi động và bắt buộc với mọi request POST.
TOKEN_HEADER = "X-Scan-Token"

# Giới hạn phía server, không tin giá trị do trình duyệt gửi lên.
MAX_PORTS = 2048
MAX_WORKERS = 100
DEFAULT_WORKERS = 100
MAX_BODY_BYTES = 65536
KEEP_JOBS = 20

# Các timeout cố định phía server để web không bị dùng làm công cụ quét nhanh.
SCAN_TIMEOUT = 1.0
BANNER_TIMEOUT = 0.5
DISCOVERY_TIMEOUT = 0.3

WEB_DIR = Path(__file__).resolve().parent / "web"
INDEX_FILE = WEB_DIR / "index.html"
TOKEN_PLACEHOLDER = "__SCAN_TOKEN__"

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


class ScanJob:
    """Trạng thái và kết quả của một lần quét chạy ở thread nền."""

    def __init__(
        self,
        target: ipaddress.IPv4Address | ipaddress.IPv4Network,
        ports: list[int],
    ) -> None:
        self.id = uuid.uuid4().hex
        self.target = target
        self.ports = list(ports)
        self.status = "running"
        self.phase = "starting"
        self.done = 0
        self.total = len(ports)
        self.message = "Đang khởi động..."
        self.records: list[ScanRecord] = []
        self.errors: list[str] = []
        self.metadata: dict[str, object] = {}
        self.started_at = current_timestamp()
        self.finished_at: str | None = None
        self.cancel_event = threading.Event()
        self._lock = threading.Lock()

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

    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def snapshot(self) -> dict:
        """Bản chụp trạng thái để trả về qua API JSON."""
        with self._lock:
            return {
                "id": self.id,
                "target": str(self.target),
                "ports": format_port_spec(self.ports),
                "status": self.status,
                "phase": self.phase,
                "message": self.message,
                "progress": {"done": self.done, "total": self.total},
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "total_open_ports": len(self.records),
                "results": [asdict(record) for record in self.records],
                "errors": list(self.errors),
                "downloads": {
                    "json": f"/api/scan/{self.id}/download?format=json",
                    "csv": f"/api/scan/{self.id}/download?format=csv",
                },
            }


def finish_job(job: ScanJob, status: str, message: str, started: float) -> None:
    """Chốt trạng thái cuối và metadata của lần quét."""
    records = job.records_snapshot()
    job.update(
        status=status,
        message=message,
        finished_at=current_timestamp(),
        metadata={
            "target": str(job.target),
            "port_range": format_port_spec(job.ports),
            "total_open_ports": len(records),
            "scan_duration_seconds": round(time.perf_counter() - started, 3),
        },
    )


def run_scan(job: ScanJob, workers: int) -> None:
    """Chạy quét trong thread nền, cập nhật tiến độ và kết quả vào job.

    Tái sử dụng nguyên logic trong scanner.py: dò host sống cho CIDR rồi quét
    cổng và đọc banner cho từng host.
    """
    started = time.perf_counter()
    errors: list[str] = []

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
                ports=DISCOVERY_PORTS,
                timeout=DISCOVERY_TIMEOUT,
                workers=workers,
                on_progress=on_discovery,
                should_cancel=job.is_cancelled,
            )

            if job.is_cancelled():
                finish_job(job, "cancelled", "Đã hủy quét.", started)
                return
            if not targets:
                finish_job(
                    job,
                    "done",
                    "Không tìm thấy host nào phản hồi nên bỏ qua quét cổng.",
                    started,
                )
                return

        total_ports = len(job.ports)
        for index, host in enumerate(targets, start=1):
            if job.is_cancelled():
                finish_job(job, "cancelled", "Đã hủy quét.", started)
                return

            job.progress(
                f"[{index}/{len(targets)}] Đang quét {host} ({total_ports} cổng)...",
                0,
                total_ports,
                "scanning",
            )

            def on_port(
                done: int,
                total: int,
                _host: str = host,
                _index: int = index,
                _count: int = len(targets),
            ) -> None:
                job.progress(
                    f"[{_index}/{_count}] {_host}: {done}/{total} cổng",
                    done,
                    total,
                    "scanning",
                )

            open_ports, port_errors = scan_ports(
                host,
                job.ports,
                timeout=SCAN_TIMEOUT,
                workers=workers,
                on_progress=on_port,
                should_cancel=job.is_cancelled,
            )
            errors.extend(f"{host}:{port} {message}" for port, message in port_errors)

            # Banner chỉ đọc cho cổng đã mở nên rất nhanh, kể cả khi vừa bị hủy.
            banners = grab_banners(
                host,
                open_ports,
                timeout=BANNER_TIMEOUT,
                workers=workers,
            )
            job.add_records(
                build_records(host, open_ports, banners, current_timestamp())
            )
            job.update(errors=list(errors))

            if job.is_cancelled():
                finish_job(job, "cancelled", "Đã hủy quét.", started)
                return

        finish_job(
            job,
            "done",
            f"Hoàn tất: {len(job.records_snapshot())} cổng mở.",
            started,
        )
    except Exception as exc:  # noqa: BLE001 - không để lộ traceback ra trình duyệt
        job.update(errors=list(errors))
        finish_job(job, "error", f"Lỗi khi quét: {exc}", started)


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
        workers: int,
    ) -> ScanJob:
        with self._lock:
            for existing in self._jobs.values():
                if existing.status == "running":
                    raise ApiError(
                        409,
                        "Đang có một lần quét chạy. Hãy đợi hoặc hủy lần quét đó trước.",
                    )
            job = ScanJob(target, ports)
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > KEEP_JOBS:
                stale = self._order.pop(0)
                self._jobs.pop(stale, None)

        thread = threading.Thread(
            target=run_scan,
            args=(job, workers),
            name=f"scan-{job.id[:8]}",
            daemon=True,
        )
        thread.start()
        return job

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

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
        if job.status == "running":
            raise ApiError(409, "Lần quét chưa hoàn tất nên chưa tải được.")

        report_format = (parse_qs(query).get("format") or ["json"])[0].lower()
        if report_format not in ("json", "csv"):
            raise ApiError(400, "Định dạng không hợp lệ; chỉ nhận json hoặc csv.")

        try:
            # Dùng lại đúng hàm định dạng mà CLI dùng để ghi báo cáo.
            text = render_report(
                report_format,
                job.records_snapshot(),
                job.metadata,
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

        workers = data.get("workers", DEFAULT_WORKERS)
        if isinstance(workers, bool) or not isinstance(workers, int):
            raise ApiError(400, "Trường 'workers' phải là số nguyên.")
        if not 1 <= workers <= MAX_WORKERS:
            raise ApiError(400, f"Trường 'workers' phải trong khoảng 1-{MAX_WORKERS}.")

        job = self.server.manager.start(target, ports, workers)
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
    """Đọc index.html và nhúng token phiên vào trang."""
    try:
        template = INDEX_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"Không đọc được {INDEX_FILE}: {exc}") from exc
    if TOKEN_PLACEHOLDER not in template:
        raise SystemExit(f"{INDEX_FILE} thiếu chỗ đánh dấu {TOKEN_PLACEHOLDER}.")
    return template.replace(TOKEN_PLACEHOLDER, token).encode("utf-8")


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
    print(f"Giới hạn: tối đa {MAX_PORTS} cổng mỗi lần quét, chỉ mục tiêu trong dải nội bộ.")
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
