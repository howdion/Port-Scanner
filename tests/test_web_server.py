"""Kiểm thử API của web server cục bộ.

Hai loại job độc lập: ``discover`` (dò host sống trong CIDR) và ``scan`` (quét
cổng trên danh sách host). Mọi bài kiểm thử chỉ nói chuyện với 127.0.0.1 và
mock phần mạng khi cần, không quét ra ngoài loopback.

Chạy:
    .venv\\Scripts\\python.exe -m unittest discover tests
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import secrets
import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

# Cho phép chạy kiểm thử từ bất kỳ thư mục nào.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main  # noqa: E402
import scanner  # noqa: E402
import web_server  # noqa: E402


class FakeBannerServer:
    """Dịch vụ TCP nhỏ trên loopback, gửi một banner cố định cho mọi kết nối.

    Cần phục vụ nhiều kết nối vì mỗi cổng được kết nối hai lần: một lần để kiểm
    tra cổng mở, một lần để đọc banner.
    """

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(8)
        self.port = self.socket.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        self.socket.settimeout(15)
        while True:
            try:
                conn, _ = self.socket.accept()
            except OSError:
                return
            try:
                conn.sendall(self.payload)
            except OSError:
                pass
            finally:
                conn.close()

    def __enter__(self) -> "FakeBannerServer":
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        try:
            self.socket.close()
        except OSError:
            pass


class WebServerTestCase(unittest.TestCase):
    """Khởi động một web server riêng trên cổng ngẫu nhiên cho mỗi bài kiểm thử."""

    def setUp(self) -> None:
        # Tắt log truy cập của server để kết quả kiểm thử dễ đọc.
        self._log_patcher = mock.patch.object(
            web_server.ScanRequestHandler,
            "log_message",
            lambda *args, **kwargs: None,
        )
        self._log_patcher.start()
        self.addCleanup(self._log_patcher.stop)

        self.token = secrets.token_urlsafe(32)
        self.auth_headers = {"X-Scan-Token": self.token}
        self.manager = web_server.JobManager()
        self.server = web_server.WebServer(
            ("127.0.0.1", 0),
            web_server.ScanRequestHandler,
            self.token,
            self.manager,
            web_server.load_index_html(self.token),
        )
        self.port = self.server.server_port
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()

    def tearDown(self) -> None:
        # Hủy mọi job còn chạy và chờ chúng dừng hẳn, để thread nền không tiếp
        # tục quét (và không lọt sang bài kiểm thử kế tiếp).
        for kind in (web_server.KIND_DISCOVER, web_server.KIND_SCAN):
            job = self.manager.running_job(kind)
            if job is not None:
                job.cancel_event.set()
        deadline = time.time() + 15
        while time.time() < deadline:
            running = [
                self.manager.running_job(web_server.KIND_DISCOVER),
                self.manager.running_job(web_server.KIND_SCAN),
            ]
            if not any(running):
                break
            time.sleep(0.05)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    # ------------------------------------------------------------------
    # Tiện ích
    # ------------------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        body: str | None = None,
        headers: dict[str, str] | None = None,
        host_header: str | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        """Gọi API và trả về (mã trạng thái, header, body)."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        request_headers = dict(headers or {})
        if body is not None:
            request_headers.setdefault("Content-Type", "application/json")
        if host_header is not None:
            request_headers["Host"] = host_header
        try:
            conn.request(method, path, body=body, headers=request_headers)
            response = conn.getresponse()
            raw = response.read()
            return response.status, dict(response.getheaders()), raw
        finally:
            conn.close()

    def post(self, path: str, payload: object) -> tuple[int, bytes]:
        status, _, raw = self.request(
            "POST", path, json.dumps(payload), self.auth_headers
        )
        return status, raw

    def post_discover(self, cidr: str, **extra: object) -> tuple[int, bytes]:
        payload: dict[str, object] = {"cidr": cidr}
        payload.update(extra)
        return self.post("/api/discover", payload)

    def post_scan(
        self,
        hosts: list[str],
        ports: str,
        **extra: object,
    ) -> tuple[int, bytes]:
        payload: dict[str, object] = {"hosts": hosts, "ports": ports}
        payload.update(extra)
        return self.post("/api/scan", payload)

    def error_of(self, raw: bytes) -> str:
        return json.loads(raw)["error"]

    def wait_done(
        self,
        kind: str,
        job_id: str,
        timeout: float = 30.0,
    ) -> dict:
        """Chờ tới khi job kết thúc và trả về bản chụp cuối."""
        deadline = time.time() + timeout
        snapshot: dict | None = None
        while time.time() < deadline:
            status, _, raw = self.request("GET", f"/api/{kind}/{job_id}")
            self.assertEqual(status, 200)
            snapshot = json.loads(raw)
            if snapshot["status"] != "running":
                return snapshot
            time.sleep(0.05)
        self.fail(f"job {kind}/{job_id} không kết thúc sau {timeout}s: {snapshot}")

    def start_scan(self, hosts: list[str], ports: str, **extra: object) -> str:
        status, raw = self.post_scan(hosts, ports, **extra)
        self.assertEqual(status, 202, f"không bắt đầu được: {raw!r}")
        return json.loads(raw)["id"]

    def start_discover(self, cidr: str, **extra: object) -> str:
        status, raw = self.post_discover(cidr, **extra)
        self.assertEqual(status, 202, f"không bắt đầu được: {raw!r}")
        return json.loads(raw)["id"]

    def cancel(self, kind: str, job_id: str) -> None:
        status, _, _ = self.request(
            "POST", f"/api/{kind}/{job_id}/cancel", None, self.auth_headers
        )
        self.assertEqual(status, 200)

    def cancel_if_running(self, kind: str, job_id: str) -> None:
        """Hủy job nếu còn chạy; bỏ qua nếu job đã kết thúc."""
        status, _, _ = self.request(
            "POST", f"/api/{kind}/{job_id}/cancel", None, self.auth_headers
        )
        if status != 409:
            self.assertEqual(status, 200)

    @staticmethod
    def slow_scan(host: str, port: int, timeout: float = 1.0) -> bool:
        """Thay cho scan_port thật: chậm và luôn báo cổng đóng."""
        time.sleep(0.05)
        return False

    @staticmethod
    def fake_scan(host: str, port: int, timeout: float = 1.0) -> bool:
        """Thay scan_port: chỉ 135 và 445 mở, không mở kết nối nào."""
        return port in (135, 445)

    @staticmethod
    def slow_fake_scan(host: str, port: int, timeout: float = 1.0) -> bool:
        """Như fake_scan nhưng chậm, để có thời gian hủy giữa các lô."""
        time.sleep(0.02)
        return port in (135, 445)


class ServerBindingTest(WebServerTestCase):
    """Server chỉ được nghe trên loopback."""

    def test_binds_loopback_only(self) -> None:
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.assertEqual(web_server.BIND_HOST, "127.0.0.1")

    def test_no_host_option_exists(self) -> None:
        parser = web_server.build_parser()
        options = {action.dest for action in parser._actions}
        self.assertNotIn("host", options)
        self.assertNotIn("bind", options)

    def test_index_page_has_token_and_security_headers(self) -> None:
        status, headers, raw = self.request("GET", "/")
        html = raw.decode("utf-8")

        self.assertEqual(status, 200)
        self.assertIn(self.token, html)
        self.assertIn("script-src 'unsafe-inline'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertNotIn("<script src=", html, "không được nạp script bên ngoài")


class TokenTest(WebServerTestCase):
    """Mọi request POST phải kèm token của phiên."""

    def test_post_without_token_is_forbidden(self) -> None:
        for path, payload in (
            ("/api/discover", {"cidr": "127.0.0.0/30"}),
            ("/api/scan", {"hosts": ["127.0.0.1"], "ports": "135"}),
        ):
            with self.subTest(path=path):
                status, _, _ = self.request("POST", path, json.dumps(payload))
                self.assertEqual(status, 403)
                self.assertIsNone(self.manager.running_job())

    def test_post_with_wrong_token_is_forbidden(self) -> None:
        status, _, _ = self.request(
            "POST",
            "/api/scan",
            json.dumps({"hosts": ["127.0.0.1"], "ports": "135"}),
            {"X-Scan-Token": "sai-token"},
        )
        self.assertEqual(status, 403)

    def test_empty_token_is_forbidden(self) -> None:
        status, _, _ = self.request(
            "POST",
            "/api/scan",
            json.dumps({"hosts": ["127.0.0.1"], "ports": "135"}),
            {"X-Scan-Token": ""},
        )
        self.assertEqual(status, 403)


class HostAndOriginTest(WebServerTestCase):
    """Chống DNS rebinding và CSRF."""

    def test_foreign_host_header_is_forbidden(self) -> None:
        status, _, _ = self.request(
            "POST",
            "/api/scan",
            json.dumps({"hosts": ["127.0.0.1"], "ports": "135"}),
            self.auth_headers,
            host_header="evil.example:8000",
        )
        self.assertEqual(status, 403)

    def test_foreign_host_on_get_is_forbidden(self) -> None:
        status, _, _ = self.request("GET", "/", host_header="evil.example:8000")
        self.assertEqual(status, 403)

    def test_host_without_port_is_forbidden(self) -> None:
        status, _, _ = self.request("GET", "/", host_header="127.0.0.1")
        self.assertEqual(status, 403)

    def test_foreign_origin_is_forbidden(self) -> None:
        status, _, _ = self.request(
            "POST",
            "/api/scan",
            json.dumps({"hosts": ["127.0.0.1"], "ports": "135"}),
            {**self.auth_headers, "Origin": "http://evil.example"},
        )
        self.assertEqual(status, 403)

    def test_matching_origin_is_accepted(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_scan):
            status, _, raw = self.request(
                "POST",
                "/api/scan",
                json.dumps({"hosts": ["127.0.0.1"], "ports": "1-40"}),
                {
                    **self.auth_headers,
                    "Origin": f"http://127.0.0.1:{self.port}",
                },
            )
        self.assertEqual(status, 202)
        job_id = json.loads(raw)["id"]
        self.cancel(web_server.KIND_SCAN, job_id)
        self.wait_done(web_server.KIND_SCAN, job_id)

    def test_missing_origin_is_accepted(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_scan):
            status, _, raw = self.request(
                "POST",
                "/api/scan",
                json.dumps({"hosts": ["127.0.0.1"], "ports": "1-40"}),
                self.auth_headers,
            )
        self.assertEqual(status, 202)
        job_id = json.loads(raw)["id"]
        self.cancel(web_server.KIND_SCAN, job_id)
        self.wait_done(web_server.KIND_SCAN, job_id)


class DiscoverValidationTest(WebServerTestCase):
    """Kiểm tra tham số của POST /api/discover."""

    def test_missing_cidr_returns_400(self) -> None:
        status, raw = self.post("/api/discover", {})
        self.assertEqual(status, 400)
        self.assertIn("cidr", self.error_of(raw))

    def test_cidr_must_be_a_string(self) -> None:
        status, raw = self.post("/api/discover", {"cidr": 123})
        self.assertEqual(status, 400)
        self.assertIn("cidr", self.error_of(raw))

    def test_single_ip_is_rejected(self) -> None:
        status, raw = self.post_discover("127.0.0.1")
        self.assertEqual(status, 400)
        self.assertIn("/api/scan", self.error_of(raw))

    def test_cidr_larger_than_slash_18_is_rejected(self) -> None:
        status, raw = self.post_discover("10.0.0.0/17")
        self.assertEqual(status, 400)
        self.assertIn("/18", self.error_of(raw))

    def test_external_cidr_is_forbidden_without_connection(self) -> None:
        calls: list[tuple[str, int]] = []

        def spy(host: str, port: int, timeout: float = 1.0) -> bool:
            calls.append((host, port))
            return False

        with mock.patch.object(scanner, "scan_port", side_effect=spy):
            status, raw = self.post_discover("8.8.8.0/24")
            self.assertEqual(status, 403)
            self.assertIn("nội bộ", self.error_of(raw))
            time.sleep(0.2)
            self.assertEqual(calls, [], "không được mở kết nối nào")
        self.assertIsNone(self.manager.running_job())

    def test_slash_18_at_boundary_is_accepted(self) -> None:
        with mock.patch.object(web_server, "discover_hosts", return_value=[]):
            job_id = self.start_discover("127.0.0.0/18")
            snapshot = self.wait_done(web_server.KIND_DISCOVER, job_id, timeout=60)
        self.assertEqual(snapshot["status"], "done")
        self.assertEqual(snapshot["cidr"], "127.0.0.0/18")
        self.assertEqual(snapshot["hosts_total"], 16382)

    def test_invalid_discovery_ports_are_rejected(self) -> None:
        for value in ("0-10", "80,,443", "1-99999", 80, ""):
            with self.subTest(value=value):
                status, raw = self.post_discover(
                    "127.0.0.0/30", discovery_ports=value
                )
                self.assertEqual(status, 400, raw)
                self.assertIn("discovery_ports", self.error_of(raw))

    def test_discovery_ports_count_is_capped(self) -> None:
        too_many = ",".join(
            str(port) for port in range(1000, 1000 + web_server.MAX_DISCOVERY_PORTS + 1)
        )
        status, raw = self.post_discover("127.0.0.0/30", discovery_ports=too_many)
        self.assertEqual(status, 400)
        self.assertIn("discovery_ports", self.error_of(raw))

    def test_discovery_timeout_range_is_enforced(self) -> None:
        for value in (0.001, 11, "1.0", True):
            with self.subTest(value=value):
                status, raw = self.post_discover(
                    "127.0.0.0/30", discovery_timeout=value
                )
                self.assertEqual(status, 400, raw)
                self.assertIn("discovery_timeout", self.error_of(raw))

    def test_concurrency_is_validated(self) -> None:
        for value in (0, web_server.MAX_CONCURRENCY + 1, "10", True):
            with self.subTest(value=value):
                status, raw = self.post_discover(
                    "127.0.0.0/30", concurrency=value
                )
                self.assertEqual(status, 400, raw)
                self.assertIn("concurrency", self.error_of(raw))

    def test_unknown_discover_id_returns_404(self) -> None:
        status, _, raw = self.request("GET", "/api/discover/khong-ton-tai")
        self.assertEqual(status, 404)
        self.assertIn("Không tìm thấy", self.error_of(raw))

    def test_scan_id_is_not_a_discover_id(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            scan_id = self.start_scan(["127.0.0.1"], "135")
            self.wait_done(web_server.KIND_SCAN, scan_id)
        status, _, _ = self.request("GET", f"/api/discover/{scan_id}")
        self.assertEqual(status, 404)


class ScanValidationTest(WebServerTestCase):
    """Kiểm tra tham số của POST /api/scan."""

    def test_missing_hosts_returns_400(self) -> None:
        status, raw = self.post("/api/scan", {"ports": "135"})
        self.assertEqual(status, 400)
        self.assertIn("hosts", self.error_of(raw))

    def test_hosts_must_be_a_list(self) -> None:
        status, raw = self.post("/api/scan", {"hosts": "127.0.0.1", "ports": "135"})
        self.assertEqual(status, 400)
        self.assertIn("hosts", self.error_of(raw))

    def test_empty_hosts_is_rejected(self) -> None:
        status, raw = self.post_scan([], "135")
        self.assertEqual(status, 400)
        self.assertIn("hosts", self.error_of(raw))

    def test_hosts_entries_must_be_strings(self) -> None:
        status, raw = self.post("/api/scan", {"hosts": [2130706433], "ports": "135"})
        self.assertEqual(status, 400)
        self.assertIn("hosts", self.error_of(raw))

    def test_cidr_inside_hosts_is_rejected(self) -> None:
        status, raw = self.post_scan(["127.0.0.0/30"], "135")
        self.assertEqual(status, 400)
        self.assertIn("CIDR", self.error_of(raw))

    def test_invalid_ip_in_hosts_is_rejected(self) -> None:
        for value in ("999.999.999.999", "khong-phai-ip", "::1", ""):
            with self.subTest(value=value):
                status, raw = self.post_scan([value], "135")
                self.assertEqual(status, 400, raw)
                self.assertTrue(self.error_of(raw))

        # IPv6 bị từ chối với thông báo riêng về họ địa chỉ.
        status, raw = self.post_scan(["::1"], "135")
        self.assertEqual(status, 400)
        self.assertIn("IPv4", self.error_of(raw))

    def test_external_host_is_forbidden_without_connection(self) -> None:
        calls: list[tuple[str, int]] = []

        def spy(host: str, port: int, timeout: float = 1.0) -> bool:
            calls.append((host, port))
            return False

        with mock.patch.object(scanner, "scan_port", side_effect=spy):
            status, raw = self.post_scan(["127.0.0.1", "8.8.8.8"], "135")
            self.assertEqual(status, 403)
            self.assertIn("8.8.8.8", self.error_of(raw))
            time.sleep(0.2)
            self.assertEqual(calls, [], "không được mở kết nối nào")
        self.assertIsNone(self.manager.running_job())

    def test_target_field_is_rejected_with_hint(self) -> None:
        status, raw = self.post(
            "/api/scan", {"target": "127.0.0.0/30", "ports": "135"}
        )
        self.assertEqual(status, 400)
        message = self.error_of(raw)
        self.assertIn("hosts", message)
        self.assertIn("/api/discover", message)

    def test_invalid_port_specs_return_400(self) -> None:
        for ports in ("0-10", "99999", "1-99999", "abc", "80,,443", ""):
            with self.subTest(ports=ports):
                status, raw = self.post_scan(["127.0.0.1"], ports)
                self.assertEqual(status, 400, raw)

    def test_concurrency_is_validated(self) -> None:
        for value in (0, web_server.MAX_CONCURRENCY + 1, "10", True):
            with self.subTest(value=value):
                status, raw = self.post_scan(
                    ["127.0.0.1"], "135", concurrency=value
                )
                self.assertEqual(status, 400, raw)
                self.assertIn("concurrency", self.error_of(raw))

    def test_unknown_scan_id_returns_404(self) -> None:
        status, _, raw = self.request("GET", "/api/scan/khong-ton-tai")
        self.assertEqual(status, 404)

    def test_discover_id_is_not_a_scan_id(self) -> None:
        with mock.patch.object(web_server, "discover_hosts", return_value=[]):
            discover_id = self.start_discover("127.0.0.0/30")
            self.wait_done(web_server.KIND_DISCOVER, discover_id)
        status, _, _ = self.request("GET", f"/api/scan/{discover_id}")
        self.assertEqual(status, 404)


class RequestValidationTest(WebServerTestCase):
    """Lỗi định dạng chung."""

    def test_malformed_json_returns_400(self) -> None:
        for path in ("/api/scan", "/api/discover"):
            with self.subTest(path=path):
                status, _, raw = self.request(
                    "POST", path, "{khong-phai-json", self.auth_headers
                )
                self.assertEqual(status, 400)
                self.assertIn("JSON", self.error_of(raw))

    def test_json_array_returns_400(self) -> None:
        for path in ("/api/scan", "/api/discover"):
            with self.subTest(path=path):
                status, _, _ = self.request(
                    "POST", path, "[1, 2, 3]", self.auth_headers
                )
                self.assertEqual(status, 400)

    def test_unknown_path_returns_404(self) -> None:
        status, _, _ = self.request("GET", "/khong-ton-tai")
        self.assertEqual(status, 404)

    def test_errors_are_json_without_traceback(self) -> None:
        status, headers, raw = self.request("GET", "/api/scan/khong-ton-tai")
        self.assertEqual(status, 404)
        self.assertTrue(headers["Content-Type"].startswith("application/json"))
        self.assertNotIn(b"Traceback", raw)
        self.assertEqual(set(json.loads(raw)), {"error"})

    def test_unknown_api_path_returns_404(self) -> None:
        status, _, _ = self.request("POST", "/api/khac", "{}", self.auth_headers)
        self.assertEqual(status, 404)


class LimitTest(WebServerTestCase):
    """Hai mốc giới hạn, tính bằng số liệu thật của từng loại job."""

    def test_discover_warning_uses_real_max_hosts(self) -> None:
        # 16.382 host × 64 cổng dò = 1.048.448: vượt mốc cảnh báo, chưa tới trần.
        discovery_ports = ",".join(str(port) for port in range(1000, 1064))
        status, raw = self.post_discover(
            "127.0.0.0/18", discovery_ports=discovery_ports
        )

        self.assertEqual(status, 202)
        payload = json.loads(raw)
        self.assertTrue(payload["confirmation_required"])
        self.assertNotIn("id", payload, "chưa được tạo job nào")
        self.assertEqual(payload["stages"], ["discovery"])
        self.assertEqual(
            payload["estimates"]["discovery"]["attempts"], 16382 * 64
        )
        self.assertIsNone(payload["estimates"]["scan"])
        self.assertIn("giai đoạn dò host sống", payload["message"])
        self.assertIsNone(self.manager.running_job())

    def test_discover_hard_cap_is_rejected_even_with_confirmation(self) -> None:
        # Hạ trần cứng để dựng nhánh từ chối của discover.
        with mock.patch.object(web_server, "HARD_ATTEMPTS", 1000), \
                mock.patch.object(main, "HARD_ATTEMPTS", 1000):
            status, raw = self.post_discover("127.0.0.0/18", confirm=True)

        self.assertEqual(status, 400)
        message = self.error_of(raw)
        self.assertIn("giai đoạn dò host sống", message)
        self.assertIn("1.000", message)
        self.assertIsNone(self.manager.running_job())

    def test_discover_warning_runs_after_confirmation(self) -> None:
        # Hạ mốc cảnh báo để job chạy nhanh trên dải nhỏ.
        with mock.patch.object(web_server, "WARN_ATTEMPTS", 5), \
                mock.patch.object(main, "WARN_ATTEMPTS", 5), \
                mock.patch.object(web_server, "discover_hosts", return_value=[]) as discover:
            job_id = self.start_discover("127.0.0.0/30", confirm=True)
            snapshot = self.wait_done(web_server.KIND_DISCOVER, job_id)

        self.assertEqual(snapshot["status"], "done")
        discover.assert_called_once()

    def test_scan_warning_uses_real_host_count(self) -> None:
        # 14 host × 65.535 cổng = 917.490: vượt mốc cảnh báo, dưới trần cứng.
        hosts = [f"127.0.0.{index}" for index in range(1, 15)]
        status, raw = self.post_scan(hosts, "1-65535")

        self.assertEqual(status, 202)
        payload = json.loads(raw)
        self.assertTrue(payload["confirmation_required"])
        self.assertNotIn("id", payload)
        self.assertEqual(payload["stages"], ["scan"])
        self.assertEqual(payload["estimates"]["scan"]["attempts"], 14 * 65535)
        self.assertIsNone(payload["estimates"]["discovery"])
        self.assertIn("giai đoạn quét cổng", payload["message"])

    def test_scan_hard_cap_is_rejected_without_connection(self) -> None:
        hosts = [f"127.0.0.{index}" for index in range(1, 101)]
        calls: list[tuple[str, int]] = []

        def spy(host: str, port: int, timeout: float = 1.0) -> bool:
            calls.append((host, port))
            return False

        with mock.patch.object(scanner, "scan_port", side_effect=spy):
            status, raw = self.post_scan(hosts, "1-65535", confirm=True)

        self.assertEqual(status, 400)
        message = self.error_of(raw)
        self.assertIn("giai đoạn quét cổng", message)
        self.assertIn("6.553.500", message)
        time.sleep(0.2)
        self.assertEqual(calls, [], "không được mở kết nối nào")
        self.assertIsNone(self.manager.running_job())

    def test_scan_warning_runs_after_confirmation(self) -> None:
        with mock.patch.object(web_server, "WARN_ATTEMPTS", 5), \
                mock.patch.object(main, "WARN_ATTEMPTS", 5), \
                mock.patch.object(scanner, "scan_port", side_effect=self.fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            job_id = self.start_scan(
                ["127.0.0.1", "127.0.0.2"], "1-10", confirm=True
            )
            snapshot = self.wait_done(web_server.KIND_SCAN, job_id)

        self.assertEqual(snapshot["status"], "done")
        self.assertEqual(snapshot["host_count"], 2)

    def test_confirmation_flag_must_be_boolean(self) -> None:
        status, raw = self.post_scan(["127.0.0.1"], "135", confirm="yes")
        self.assertEqual(status, 400)
        self.assertIn("confirm", self.error_of(raw))


class ConcurrentJobsTest(WebServerTestCase):
    """Mỗi loại chỉ một job tại một thời điểm; hai loại chạy được song song."""

    def test_second_scan_returns_conflict(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_scan):
            job_id = self.start_scan(["127.0.0.1"], "1-400", concurrency=1)

            status, raw = self.post_scan(["127.0.0.1"], "135")
            self.assertEqual(status, 409)
            self.assertIn("Đang có một lần quét", self.error_of(raw))

            self.cancel_if_running(web_server.KIND_SCAN, job_id)
            self.wait_done(web_server.KIND_SCAN, job_id, timeout=60)

    def test_second_discover_returns_conflict(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_scan):
            job_id = self.start_discover("127.0.0.0/28", concurrency=1)

            status, raw = self.post_discover("127.0.0.0/30")
            self.assertEqual(status, 409)
            self.assertIn("Đang có một lần dò host", self.error_of(raw))

            self.cancel_if_running(web_server.KIND_DISCOVER, job_id)
            self.wait_done(web_server.KIND_DISCOVER, job_id, timeout=60)

    def test_discover_and_scan_can_run_together(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_scan):
            discover_id = self.start_discover("127.0.0.0/28", concurrency=1)
            scan_id = self.start_scan(["127.0.0.1"], "1-400", concurrency=1)

            self.assertIsNotNone(
                self.manager.running_job(web_server.KIND_DISCOVER)
            )
            self.assertIsNotNone(self.manager.running_job(web_server.KIND_SCAN))

            self.cancel_if_running(web_server.KIND_DISCOVER, discover_id)
            self.cancel_if_running(web_server.KIND_SCAN, scan_id)
            self.wait_done(web_server.KIND_DISCOVER, discover_id, timeout=60)
            self.wait_done(web_server.KIND_SCAN, scan_id, timeout=60)

    def test_scan_can_start_again_after_finishing(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            first = self.start_scan(["127.0.0.1"], "135")
            self.wait_done(web_server.KIND_SCAN, first)

            second = self.start_scan(["127.0.0.1"], "445")
            self.wait_done(web_server.KIND_SCAN, second)

        self.assertNotEqual(first, second)


class CancelTest(WebServerTestCase):
    """Hủy job đang chạy, không hủy được job đã xong."""

    def test_cancel_running_scan(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_scan):
            job_id = self.start_scan(["127.0.0.1"], "1-400", concurrency=1)
            self.cancel(web_server.KIND_SCAN, job_id)
            snapshot = self.wait_done(web_server.KIND_SCAN, job_id, timeout=60)

        self.assertEqual(snapshot["status"], "cancelled")
        self.assertIn("Đã hủy", snapshot["message"])

    def test_cancel_running_discover(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_scan):
            job_id = self.start_discover("127.0.0.0/28", concurrency=1)
            self.cancel(web_server.KIND_DISCOVER, job_id)
            snapshot = self.wait_done(web_server.KIND_DISCOVER, job_id, timeout=60)

        self.assertEqual(snapshot["status"], "cancelled")
        self.assertIn("Đã hủy", snapshot["message"])

    def test_cancel_finished_scan_returns_conflict(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            job_id = self.start_scan(["127.0.0.1"], "135")
            self.wait_done(web_server.KIND_SCAN, job_id)

        status, _, _ = self.request(
            "POST", f"/api/scan/{job_id}/cancel", None, self.auth_headers
        )
        self.assertEqual(status, 409)

    def test_cancel_unknown_scan_returns_404(self) -> None:
        status, _, _ = self.request(
            "POST", "/api/scan/khong-ton-tai/cancel", None, self.auth_headers
        )
        self.assertEqual(status, 404)

    def test_cancel_requires_token(self) -> None:
        status, _, _ = self.request("POST", "/api/scan/khong-ton-tai/cancel", None)
        self.assertEqual(status, 403)


class DiscoverResultTest(WebServerTestCase):
    """Job discover trả về danh sách host sống."""

    def test_discover_returns_live_hosts(self) -> None:
        with mock.patch.object(
            web_server, "discover_hosts", return_value=["127.0.0.1", "127.0.0.2"]
        ) as discover:
            job_id = self.start_discover("127.0.0.0/30", discovery_ports="135")
            snapshot = self.wait_done(web_server.KIND_DISCOVER, job_id)

        self.assertEqual(snapshot["status"], "done")
        self.assertEqual(snapshot["kind"], "discover")
        self.assertEqual(snapshot["cidr"], "127.0.0.0/30")
        self.assertEqual(snapshot["live_hosts"], ["127.0.0.1", "127.0.0.2"])
        self.assertEqual(snapshot["total_live_hosts"], 2)
        self.assertEqual(snapshot["hosts_total"], 2)
        self.assertNotIn("results", snapshot)
        self.assertEqual(snapshot["params"]["discovery_ports"], "135")
        discover.assert_called_once()

    def test_discover_does_not_scan_ports(self) -> None:
        with mock.patch.object(web_server, "discover_hosts", return_value=[]), \
                mock.patch.object(scanner, "scan_port") as scan_port:
            job_id = self.start_discover("127.0.0.0/30")
            self.wait_done(web_server.KIND_DISCOVER, job_id)

        scan_port.assert_not_called()


class ScanResultTest(WebServerTestCase):
    """Luồng quét đầy đủ và dữ liệu trả về."""

    def test_scan_loopback_ports_and_download(self) -> None:
        with FakeBannerServer(b"demo banner\r\n") as fake:
            job_id = self.start_scan(["127.0.0.1"], str(fake.port))
            snapshot = self.wait_done(web_server.KIND_SCAN, job_id)

        self.assertEqual(snapshot["status"], "done")
        self.assertEqual(snapshot["hosts"], ["127.0.0.1"])
        self.assertEqual(len(snapshot["results"]), 1)
        record = snapshot["results"][0]
        self.assertEqual(
            set(record),
            {"host", "port", "protocol", "service", "banner", "scanned_at"},
        )
        self.assertEqual(record["host"], "127.0.0.1")
        self.assertEqual(record["port"], fake.port)
        self.assertEqual(record["banner"], "demo banner")

        status, headers, raw = self.request(
            "GET",
            f"/api/scan/{job_id}/download?format=json",
            headers=self.auth_headers,
        )
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers["Content-Disposition"])
        document = json.loads(raw)
        self.assertEqual(set(document), {"metadata", "results"})
        self.assertEqual(
            document["metadata"]["total_open_ports"], len(document["results"])
        )
        self.assertNotIn(b"Traceback", raw)

    def test_multi_host_scan_returns_all_hosts(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            job_id = self.start_scan(
                ["127.0.0.1", "127.0.0.2", "127.0.0.3"], "135,445"
            )
            snapshot = self.wait_done(web_server.KIND_SCAN, job_id)

        self.assertEqual(snapshot["status"], "done")
        self.assertEqual(snapshot["host_count"], 3)
        self.assertEqual(
            sorted({r["host"] for r in snapshot["results"]}),
            ["127.0.0.1", "127.0.0.2", "127.0.0.3"],
        )
        self.assertEqual(len(snapshot["results"]), 6)

    def test_results_sorted_by_ip_then_port(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            job_id = self.start_scan(["127.0.0.2", "127.0.0.1"], "1-4096")
            snapshot = self.wait_done(web_server.KIND_SCAN, job_id)

        keys = [(int(r["host"].split(".")[-1]), r["port"]) for r in snapshot["results"]]
        self.assertEqual(keys, sorted(keys))

    def test_duplicate_hosts_are_deduplicated(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            job_id = self.start_scan(
                ["127.0.0.1", "127.0.0.1", " 127.0.0.1 "], "135"
            )
            snapshot = self.wait_done(web_server.KIND_SCAN, job_id)

        self.assertEqual(snapshot["host_count"], 1)
        self.assertEqual(len(snapshot["results"]), 1)

    def test_banner_with_html_is_returned_verbatim_as_data(self) -> None:
        payload = b'<img src=x onerror=alert(1)><script>alert(2)</script>\r\n'
        with FakeBannerServer(payload) as fake:
            job_id = self.start_scan(["127.0.0.1"], str(fake.port))
            snapshot = self.wait_done(web_server.KIND_SCAN, job_id)

        self.assertEqual(snapshot["status"], "done")
        record = snapshot["results"][0]
        self.assertIn("<img src=x onerror=alert(1)>", record["banner"])
        self.assertIn("<script>alert(2)</script>", record["banner"])

        # Dữ liệu vẫn là JSON hợp lệ và không bị mã hóa lại; việc chống XSS do
        # giao diện lo bằng textContent, không phải bằng cách sửa dữ liệu.
        status, _, final_raw = self.request("GET", f"/api/scan/{job_id}")
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(final_raw)["results"][0]["banner"], record["banner"]
        )

    def test_download_requires_token(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            job_id = self.start_scan(["127.0.0.1"], "135")
            self.wait_done(web_server.KIND_SCAN, job_id)

        status, _, _ = self.request(
            "GET", f"/api/scan/{job_id}/download?format=json"
        )
        self.assertEqual(status, 403)

    def test_download_csv(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            job_id = self.start_scan(["127.0.0.1"], "135")
            self.wait_done(web_server.KIND_SCAN, job_id)

        status, headers, raw = self.request(
            "GET",
            f"/api/scan/{job_id}/download?format=csv",
            headers=self.auth_headers,
        )
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/csv"))
        self.assertIn(b"host,port,protocol,service,banner,scanned_at", raw)

    def test_download_on_discover_job_returns_404(self) -> None:
        with mock.patch.object(web_server, "discover_hosts", return_value=[]):
            job_id = self.start_discover("127.0.0.0/30")
            self.wait_done(web_server.KIND_DISCOVER, job_id)

        status, _, _ = self.request(
            "GET", f"/api/scan/{job_id}/download?format=json", headers=self.auth_headers
        )
        self.assertEqual(status, 404)


class BatchScanTest(WebServerTestCase):
    """Quét theo lô: chia cổng, kết quả từng phần, hủy giữa các lô."""

    def test_single_batch_for_exactly_one_batch_of_ports(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            job_id = self.start_scan(["127.0.0.1"], f"1-{web_server.BATCH_SIZE}")
            snapshot = self.wait_done(web_server.KIND_SCAN, job_id)

        self.assertEqual(snapshot["batch"]["total"], 1)
        self.assertEqual(snapshot["batch"]["index"], 1)
        self.assertEqual(snapshot["batch"]["ports_total"], web_server.BATCH_SIZE)
        self.assertEqual(snapshot["batch"]["ports_done"], web_server.BATCH_SIZE)

    def test_two_batches_at_boundary(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            job_id = self.start_scan(
                ["127.0.0.1"], f"1-{web_server.BATCH_SIZE + 1}"
            )
            snapshot = self.wait_done(web_server.KIND_SCAN, job_id)

        self.assertEqual(snapshot["batch"]["total"], 2)
        self.assertEqual(snapshot["batch"]["port_range"], "2049")
        self.assertEqual(snapshot["status"], "done")

    def test_discrete_ports_are_split_correctly(self) -> None:
        # 3 cổng rời (22, 80, 443) + 2501 cổng liền (3000-5500) = 2504 cổng.
        with mock.patch.object(scanner, "scan_port", side_effect=self.fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            job_id = self.start_scan(["127.0.0.1"], "22,80,443,3000-5500")
            snapshot = self.wait_done(web_server.KIND_SCAN, job_id)

        self.assertEqual(snapshot["batch"]["total"], 2)
        self.assertEqual(snapshot["batch"]["ports_total"], 2504)
        self.assertEqual(snapshot["batch"]["port_range"], "5045-5500")

    def test_results_appear_after_first_batch(self) -> None:
        seen_batches: list[int] = []
        partial_results: list[list[int]] = []

        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            job_id = self.start_scan(["127.0.0.1"], "1-4096")
            deadline = time.time() + 60
            snapshot: dict = {}
            while time.time() < deadline:
                _, _, raw = self.request("GET", f"/api/scan/{job_id}")
                snapshot = json.loads(raw)
                index = (snapshot.get("batch") or {}).get("index", 0)
                if index and index not in seen_batches:
                    seen_batches.append(index)
                if snapshot["status"] == "running":
                    ports = sorted(r["port"] for r in snapshot["results"])
                    if ports:
                        partial_results.append(ports)
                else:
                    break
                time.sleep(0.05)

        self.assertEqual(snapshot["status"], "done")
        self.assertEqual(seen_batches, [1, 2], "phải đi qua lô 1 rồi lô 2")
        self.assertTrue(
            any(ports == [135, 445] for ports in partial_results),
            f"kết quả lô 1 phải xuất hiện khi job còn chạy: {partial_results}",
        )
        self.assertEqual(snapshot["batch"]["ports_done"], 4096)

    def test_cancel_between_batches_keeps_finished_results(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            job_id = self.start_scan(["127.0.0.1"], "1-4096")

            # Chờ lô 1 xong (job đã sang lô 2) rồi hủy.
            deadline = time.time() + 60
            while time.time() < deadline:
                _, _, raw = self.request("GET", f"/api/scan/{job_id}")
                if (json.loads(raw).get("batch") or {}).get("index", 0) >= 2:
                    break
                time.sleep(0.05)
            self.cancel(web_server.KIND_SCAN, job_id)
            snapshot = self.wait_done(web_server.KIND_SCAN, job_id, timeout=60)

        self.assertEqual(snapshot["status"], "cancelled")
        self.assertEqual(snapshot["batch"]["completed"], 1)
        self.assertEqual(
            sorted(r["port"] for r in snapshot["results"]),
            [135, 445],
            "kết quả của lô đã xong phải được giữ lại",
        )

    def test_download_while_running_returns_partial_results(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_fake_scan), \
                mock.patch.object(scanner, "grab_banner", return_value=None):
            job_id = self.start_scan(["127.0.0.1"], "1-4096", concurrency=5)

            deadline = time.time() + 60
            while time.time() < deadline:
                _, _, raw = self.request("GET", f"/api/scan/{job_id}")
                if (json.loads(raw).get("batch") or {}).get("ports_done", 0) >= 1:
                    break
                time.sleep(0.05)

            status, _, download = self.request(
                "GET",
                f"/api/scan/{job_id}/download?format=json",
                headers=self.auth_headers,
            )
            self.assertEqual(status, 200)
            document = json.loads(download)
            self.assertEqual(
                document["metadata"]["batches_total"], 2
            )

            self.cancel_if_running(web_server.KIND_SCAN, job_id)
            self.wait_done(web_server.KIND_SCAN, job_id, timeout=60)

    def test_batch_fields_present_in_cancel_response(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_scan):
            job_id = self.start_scan(["127.0.0.1"], "1-400", concurrency=1)
            status, _, raw = self.request(
                "POST", f"/api/scan/{job_id}/cancel", None, self.auth_headers
            )
            self.assertEqual(status, 200)
            body = json.loads(raw)
            self.assertTrue(body["cancelled"])
            payload = body["job"]
            self.assertIn("batch", payload)
            self.assertIn("ports_total", payload["batch"])
            self.wait_done(web_server.KIND_SCAN, job_id, timeout=60)


if __name__ == "__main__":
    unittest.main()
