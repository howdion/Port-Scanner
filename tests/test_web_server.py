"""Kiểm thử API của web server cục bộ.

Mọi bài kiểm thử chỉ nói chuyện với 127.0.0.1: server được bind trên loopback với
cổng ngẫu nhiên, và không bài nào quét ra ngoài loopback.

Chạy:
    .venv\\Scripts\\python.exe -m unittest discover tests
"""

from __future__ import annotations

import http.client
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
        self.manager = web_server.ScanManager()
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

    def post_scan(self, target: str, ports: str, **extra: object) -> tuple[int, bytes]:
        payload: dict[str, object] = {"target": target, "ports": ports}
        payload.update(extra)
        status, _, raw = self.request(
            "POST",
            "/api/scan",
            json.dumps(payload),
            self.auth_headers,
        )
        return status, raw

    def error_of(self, raw: bytes) -> str:
        return json.loads(raw)["error"]

    def wait_done(self, job_id: str, timeout: float = 30.0) -> dict:
        """Chờ tới khi lần quét kết thúc và trả về bản chụp cuối."""
        deadline = time.time() + timeout
        snapshot: dict | None = None
        while time.time() < deadline:
            status, _, raw = self.request("GET", f"/api/scan/{job_id}")
            self.assertEqual(status, 200)
            snapshot = json.loads(raw)
            if snapshot["status"] != "running":
                return snapshot
            time.sleep(0.05)
        self.fail(f"lần quét {job_id} không kết thúc sau {timeout}s: {snapshot}")

    @staticmethod
    def slow_scan(host: str, port: int, timeout: float = 1.0) -> bool:
        """Thay cho scan_port thật: chậm và luôn báo cổng đóng."""
        time.sleep(0.05)
        return False


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
        self.assertNotIn(web_server.TOKEN_PLACEHOLDER, html)
        self.assertTrue(
            headers["Content-Security-Policy"].startswith("default-src 'none'")
        )
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")


class TokenTest(WebServerTestCase):
    """Token bắt buộc với mọi request POST và khi tải kết quả."""

    def test_post_without_token_is_forbidden(self) -> None:
        status, _, raw = self.request(
            "POST",
            "/api/scan",
            json.dumps({"target": "127.0.0.1", "ports": "135"}),
        )
        self.assertEqual(status, 403)
        self.assertIn("token", self.error_of(raw).lower())

    def test_post_with_wrong_token_is_forbidden(self) -> None:
        status, _, raw = self.request(
            "POST",
            "/api/scan",
            json.dumps({"target": "127.0.0.1", "ports": "135"}),
            {"X-Scan-Token": "token-sai"},
        )
        self.assertEqual(status, 403)

    def test_empty_token_is_forbidden(self) -> None:
        status, _, _ = self.request(
            "POST",
            "/api/scan",
            json.dumps({"target": "127.0.0.1", "ports": "135"}),
            {"X-Scan-Token": ""},
        )
        self.assertEqual(status, 403)


class HostAndOriginTest(WebServerTestCase):
    """Chặn trang web khác lợi dụng API (Host/Origin lạ)."""

    def setUp(self) -> None:
        super().setUp()
        self.valid_body = json.dumps({"target": "127.0.0.1", "ports": "135"})

    def test_foreign_host_header_is_forbidden(self) -> None:
        status, _, raw = self.request(
            "POST",
            "/api/scan",
            self.valid_body,
            self.auth_headers,
            host_header="evil.example.com",
        )
        self.assertEqual(status, 403)
        self.assertIn("Host", self.error_of(raw))

    def test_foreign_host_on_get_is_forbidden(self) -> None:
        status, _, _ = self.request("GET", "/", host_header="evil.example.com")
        self.assertEqual(status, 403)

    def test_host_without_port_is_forbidden(self) -> None:
        status, _, _ = self.request(
            "POST",
            "/api/scan",
            self.valid_body,
            self.auth_headers,
            host_header="127.0.0.1",
        )
        self.assertEqual(status, 403)

    def test_foreign_origin_is_forbidden(self) -> None:
        headers = dict(self.auth_headers)
        headers["Origin"] = "http://evil.example.com"
        status, _, raw = self.request("POST", "/api/scan", self.valid_body, headers)
        self.assertEqual(status, 403)
        self.assertIn("Origin", self.error_of(raw))

    def test_matching_origin_is_accepted(self) -> None:
        headers = dict(self.auth_headers)
        headers["Origin"] = f"http://127.0.0.1:{self.port}"
        status, _, raw = self.request("POST", "/api/scan", self.valid_body, headers)
        self.assertEqual(status, 202)
        self.wait_done(json.loads(raw)["id"])

    def test_missing_origin_is_accepted(self) -> None:
        # curl hoặc script không gửi Origin; token vẫn là điều kiện bắt buộc.
        status, _, raw = self.request("POST", "/api/scan", self.valid_body, self.auth_headers)
        self.assertEqual(status, 202)
        self.wait_done(json.loads(raw)["id"])


class TargetRestrictionTest(WebServerTestCase):
    """Giới hạn mục tiêu được kiểm tra ở phía server."""

    def test_external_target_is_forbidden_without_any_connection(self) -> None:
        calls: list[tuple[str, int]] = []

        def spy(host: str, port: int, timeout: float = 1.0) -> bool:
            calls.append((host, port))
            return False

        with mock.patch.object(scanner, "scan_port", side_effect=spy):
            status, raw = self.post_scan("8.8.8.8", "53")
            self.assertEqual(status, 403)
            self.assertIn("nội bộ", self.error_of(raw))

            # Cho thread (nếu lỡ được tạo) thời gian gọi scan_port.
            time.sleep(0.3)
            self.assertEqual(calls, [], "không được kết nối ra ngoài dải nội bộ")

            # Không có lần quét nào đang chạy -> yêu cầu hợp lệ tiếp theo được nhận.
            status2, raw2 = self.post_scan("127.0.0.1", "135")
            self.assertEqual(status2, 202)
            self.wait_done(json.loads(raw2)["id"])
            self.assertTrue(all(host == "127.0.0.1" for host, _ in calls))

    def test_other_external_targets_are_forbidden(self) -> None:
        for target in ("1.1.1.1", "172.32.0.1", "192.169.0.1", "8.8.8.0/24"):
            with self.subTest(target=target):
                status, raw = self.post_scan(target, "80")
                self.assertEqual(status, 403)
                self.assertIn("nội bộ", self.error_of(raw))

    def test_internal_targets_are_accepted_at_validation(self) -> None:
        # Chỉ kiểm tra qua lớp kiểm tra mục tiêu, không quét cổng thật.
        for target in ("127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1"):
            with self.subTest(target=target):
                parsed = web_server.parse_target(target)
                self.assertTrue(web_server.is_internal(parsed))

    def test_cidr_larger_than_slash_24_is_rejected(self) -> None:
        for target in ("10.0.0.0/16", "192.168.0.0/23", "127.0.0.0/8"):
            with self.subTest(target=target):
                status, raw = self.post_scan(target, "80")
                self.assertEqual(status, 400)
                self.assertIn("/24", self.error_of(raw))

    def test_cidr_slash_24_at_boundary_is_accepted(self) -> None:
        # Dùng scan_port giả để không thật sự dò 254 host.
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_scan):
            status, raw = self.post_scan("127.0.0.0/24", "135")
            self.assertEqual(status, 202)
            job_id = json.loads(raw)["id"]
            self.request("POST", f"/api/scan/{job_id}/cancel", None, self.auth_headers)
            self.wait_done(job_id)

    def test_invalid_ip_is_rejected(self) -> None:
        for target in ("999.999.999.999", "khong-phai-ip", "::1", ""):
            with self.subTest(target=target):
                status, _ = self.post_scan(target, "80")
                self.assertEqual(status, 400)


class RequestValidationTest(WebServerTestCase):
    """Lỗi đầu vào trả mã rõ ràng, không lộ traceback."""

    def test_malformed_json_returns_400(self) -> None:
        status, _, raw = self.request("POST", "/api/scan", "{khong-phai-json", self.auth_headers)
        self.assertEqual(status, 400)
        self.assertIn("JSON", self.error_of(raw))

    def test_json_array_returns_400(self) -> None:
        status, _, raw = self.request("POST", "/api/scan", "[1, 2, 3]", self.auth_headers)
        self.assertEqual(status, 400)

    def test_missing_fields_return_400(self) -> None:
        for payload in ({}, {"target": "127.0.0.1"}, {"ports": "80"}):
            with self.subTest(payload=payload):
                status, _, raw = self.request(
                    "POST", "/api/scan", json.dumps(payload), self.auth_headers
                )
                self.assertEqual(status, 400)

    def test_wrong_field_types_return_400(self) -> None:
        for payload in (
            {"target": "127.0.0.1", "ports": 80},
            {"target": 2130706433, "ports": "80"},
            {"target": "127.0.0.1", "ports": "80", "workers": "nhieu"},
            {"target": "127.0.0.1", "ports": "80", "workers": None},
            {"target": "127.0.0.1", "ports": "80", "workers": True},
        ):
            with self.subTest(payload=payload):
                status, _, _ = self.request(
                    "POST", "/api/scan", json.dumps(payload), self.auth_headers
                )
                self.assertEqual(status, 400)

    def test_invalid_port_specs_return_400(self) -> None:
        for ports in ("0-10", "99999", "1-99999", "abc", "80,,443", ""):
            with self.subTest(ports=ports):
                status, _ = self.post_scan("127.0.0.1", ports)
                self.assertEqual(status, 400)

    def test_unknown_job_id_returns_404(self) -> None:
        status, _, raw = self.request("GET", "/api/scan/khong-ton-tai")
        self.assertEqual(status, 404)
        self.assertIn("Không tìm thấy", self.error_of(raw))

    def test_unknown_path_returns_404(self) -> None:
        status, _, _ = self.request("GET", "/khong-ton-tai")
        self.assertEqual(status, 404)

    def test_errors_are_json_without_traceback(self) -> None:
        status, headers, raw = self.request("GET", "/api/scan/khong-ton-tai")
        self.assertEqual(status, 404)
        self.assertTrue(headers["Content-Type"].startswith("application/json"))
        self.assertNotIn(b"Traceback", raw)
        self.assertEqual(set(json.loads(raw)), {"error"})


class LimitsTest(WebServerTestCase):
    """Giới hạn số cổng và số luồng do server quyết định."""

    def test_too_many_ports_is_rejected(self) -> None:
        status, raw = self.post_scan("127.0.0.1", "1-65535")
        self.assertEqual(status, 400)
        self.assertIn("tối đa", self.error_of(raw))

    def test_workers_above_limit_is_rejected(self) -> None:
        status, raw = self.post_scan("127.0.0.1", "80", workers=web_server.MAX_WORKERS + 1)
        self.assertEqual(status, 400)
        self.assertIn("workers", self.error_of(raw))

    def test_workers_zero_is_rejected(self) -> None:
        status, raw = self.post_scan("127.0.0.1", "80", workers=0)
        self.assertEqual(status, 400)
        self.assertIn("workers", self.error_of(raw))

    def test_workers_at_limit_is_accepted(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_scan):
            status, raw = self.post_scan(
                "127.0.0.1", "1-200", workers=web_server.MAX_WORKERS
            )
            self.assertEqual(status, 202)
            job_id = json.loads(raw)["id"]
            self.request("POST", f"/api/scan/{job_id}/cancel", None, self.auth_headers)
            self.wait_done(job_id)

    def test_port_count_at_limit_is_accepted(self) -> None:
        ports = f"1-{web_server.MAX_PORTS}"
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_scan):
            status, raw = self.post_scan("127.0.0.1", ports)
            self.assertEqual(status, 202)
            job_id = json.loads(raw)["id"]
            snapshot = json.loads(
                self.request("GET", f"/api/scan/{job_id}")[2]
            )
            self.assertEqual(snapshot["progress"]["total"], web_server.MAX_PORTS)
            self.request("POST", f"/api/scan/{job_id}/cancel", None, self.auth_headers)
            self.wait_done(job_id)

    def test_port_count_over_limit_by_one_is_rejected(self) -> None:
        ports = f"1-{web_server.MAX_PORTS + 1}"
        status, raw = self.post_scan("127.0.0.1", ports)
        self.assertEqual(status, 400)
        self.assertIn("tối đa", self.error_of(raw))


class SingleScanAtATimeTest(WebServerTestCase):
    """Mỗi lúc chỉ một lần quét; yêu cầu thứ hai nhận 409."""

    def test_second_scan_returns_conflict(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_scan):
            status, raw = self.post_scan("127.0.0.1", "1-1024")
            self.assertEqual(status, 202)
            job_id = json.loads(raw)["id"]

            status2, _, raw2 = self.request(
                "POST",
                "/api/scan",
                json.dumps({"target": "127.0.0.1", "ports": "135"}),
                self.auth_headers,
            )
            self.assertEqual(status2, 409)
            self.assertIn("Đang có một lần quét chạy", self.error_of(raw2))

            # Yêu cầu bị từ chối không được tạo job mới.
            self.assertEqual(self.manager.get(job_id).status, "running")

            self.request("POST", f"/api/scan/{job_id}/cancel", None, self.auth_headers)
            self.wait_done(job_id)

    def test_scan_can_start_again_after_finishing(self) -> None:
        status, raw = self.post_scan("127.0.0.1", "135")
        self.assertEqual(status, 202)
        self.wait_done(json.loads(raw)["id"])

        status2, raw2 = self.post_scan("127.0.0.1", "445")
        self.assertEqual(status2, 202)
        self.wait_done(json.loads(raw2)["id"])


class CancelTest(WebServerTestCase):
    """Hủy lần quét đang chạy."""

    def test_cancel_running_scan(self) -> None:
        with mock.patch.object(scanner, "scan_port", side_effect=self.slow_scan):
            status, raw = self.post_scan("127.0.0.1", "1-1024")
            self.assertEqual(status, 202)
            job_id = json.loads(raw)["id"]

            status, _, raw = self.request(
                "POST", f"/api/scan/{job_id}/cancel", None, self.auth_headers
            )
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(raw)["cancelled"])

            snapshot = self.wait_done(job_id)
            self.assertEqual(snapshot["status"], "cancelled")

    def test_cancel_finished_scan_returns_conflict(self) -> None:
        status, raw = self.post_scan("127.0.0.1", "135")
        job_id = json.loads(raw)["id"]
        self.wait_done(job_id)

        status, _, raw = self.request(
            "POST", f"/api/scan/{job_id}/cancel", None, self.auth_headers
        )
        self.assertEqual(status, 409)

    def test_cancel_unknown_scan_returns_404(self) -> None:
        status, _, _ = self.request(
            "POST", "/api/scan/khong-ton-tai/cancel", None, self.auth_headers
        )
        self.assertEqual(status, 404)


class ScanResultTest(WebServerTestCase):
    """Luồng quét đầy đủ và dữ liệu trả về."""

    def test_scan_loopback_ports_and_download(self) -> None:
        status, raw = self.post_scan("127.0.0.1", "135,445")
        self.assertEqual(status, 202)
        job_id = json.loads(raw)["id"]

        snapshot = self.wait_done(job_id)
        self.assertEqual(snapshot["status"], "done")
        self.assertEqual(sorted(r["port"] for r in snapshot["results"]), [135, 445])
        self.assertEqual(
            sorted(r["service"] for r in snapshot["results"]),
            ["microsoft-ds", "msrpc"],
        )
        for record in snapshot["results"]:
            self.assertEqual(
                set(record),
                {"host", "port", "protocol", "service", "banner", "scanned_at"},
            )
            self.assertEqual(record["protocol"], "tcp")
            self.assertEqual(record["host"], "127.0.0.1")

        status, headers, raw = self.request(
            "GET", f"/api/scan/{job_id}/download?format=json", headers=self.auth_headers
        )
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers["Content-Disposition"])
        document = json.loads(raw)
        self.assertEqual(set(document), {"metadata", "results"})
        self.assertEqual(document["metadata"]["total_open_ports"], len(document["results"]))
        self.assertNotIn(b"Traceback", raw)

    def test_cidr_scan_covers_hosts(self) -> None:
        status, raw = self.post_scan("127.0.0.0/30", "135,445")
        self.assertEqual(status, 202)
        snapshot = self.wait_done(json.loads(raw)["id"], timeout=60)
        self.assertEqual(snapshot["status"], "done")
        self.assertEqual(
            sorted({r["host"] for r in snapshot["results"]}),
            ["127.0.0.1", "127.0.0.2"],
        )

    def test_banner_with_html_is_returned_verbatim_as_data(self) -> None:
        payload = b'<img src=x onerror=alert(1)><script>alert(2)</script>\r\n'
        with FakeBannerServer(payload) as fake:
            status, raw = self.post_scan("127.0.0.1", str(fake.port))
            self.assertEqual(status, 202)
            job_id = json.loads(raw)["id"]
            snapshot = self.wait_done(job_id)

        self.assertEqual(snapshot["status"], "done")
        self.assertEqual(len(snapshot["results"]), 1)
        record = snapshot["results"][0]
        self.assertEqual(record["service"], "unknown")
        self.assertIsNotNone(record["banner"])
        self.assertIn("<img src=x onerror=alert(1)>", record["banner"])
        self.assertIn("<script>alert(2)</script>", record["banner"])

        # Dữ liệu vẫn là JSON hợp lệ và không bị mã hóa lại; việc chống XSS do
        # giao diện lo bằng textContent, không phải bằng cách sửa dữ liệu.
        status, _, final_raw = self.request("GET", f"/api/scan/{job_id}")
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(final_raw)["results"][0]["banner"],
            record["banner"],
        )


if __name__ == "__main__":
    unittest.main()
