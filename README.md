# Port Scanner

Công cụ quét cổng TCP dùng để học về mạng máy tính, đặc biệt là TCP handshake
và lập trình socket. Chương trình nhận một địa chỉ IPv4 hoặc một dải CIDR, kiểm
tra cổng nào đang mở bằng TCP connect, có timeout cho từng kết nối và quét song
song bằng thread pool. Với mỗi cổng mở, chương trình hiển thị tên dịch vụ và thử
đọc banner ngắn. Với CIDR, chương trình dò nhanh các host còn sống trước khi quét
cổng. Kết quả có thể xuất ra báo cáo JSON/CSV.

> Hiện tại: CLI quét IPv4 hoặc CIDR từ `/18` đến `/32`, tối đa 65535 cổng mỗi lần quét,
> có hai mốc giới hạn tổng lượt quét (cảnh báo ở 500.000 và trần cứng 5.000.000), nhận
> diện dịch vụ, banner, dò host sống, xuất báo cáo JSON/CSV, kèm giao diện web cục bộ.
> Bước 1–5 đã hoàn thành.

## Yêu cầu

- Python 3.11 trở lên.
- Chỉ dùng thư viện chuẩn của Python, không cần cài thêm gói.

## Cài đặt

```powershell
git clone https://github.com/howdion/Port-Scanner.git
cd Port-Scanner
```

## Cấu trúc thư mục

```text
Port Scanner/
├── .gitignore
├── AGENTS.md          # hướng dẫn nội bộ cho agent
├── main.py            # CLI, tham số, điều phối quét
├── report.py          # xuất báo cáo JSON/CSV
├── scanner.py         # quét cổng, dò host, đọc banner
├── services.py        # bảng ánh xạ cổng → tên dịch vụ
├── web_server.py      # web server cục bộ, chỉ bind 127.0.0.1
├── README.md
├── tests/             # kiểm thử tự động bằng unittest
│   ├── test_batching.py
│   ├── test_limits.py
│   ├── test_parsing.py
│   ├── test_report.py
│   └── test_web_server.py
├── web/
│   └── index.html     # giao diện web: HTML + CSS + JS thuần, một file
├── .venv/             # môi trường ảo (tự setup nếu muốn, không commit)
├── __pycache__/       # cache Python (không commit)
└── reports/           # báo cáo sinh ra (không commit)
```

## Kiểm thử

Bộ kiểm thử dùng `unittest` của thư viện chuẩn, không cần cài thêm gói:

```powershell
python -m unittest discover tests
```

- `tests/test_parsing.py`: phân tích mục tiêu (IPv4/CIDR) và dải cổng, kiểm tra dải nội bộ.
- `tests/test_report.py`: dựng và ghi báo cáo JSON/CSV, xử lý ký tự đặc biệt trong banner.
- `tests/test_web_server.py`: API của web server — token, Host/Origin, giới hạn mục tiêu,
  giới hạn số cổng và số luồng, hai lần quét cùng lúc, hủy quét, banner chứa HTML,
  quét theo lô (chia lô, kết quả từng phần, hủy giữa các lô, giới hạn tổng lượt thử).
- `tests/test_batching.py`: hàm chia lô cổng, đếm host của mục tiêu, sắp xếp kết quả theo IP.
- `tests/test_limits.py`: hai mốc giới hạn tổng lượt quét, các hàm ước tính lượt và ước
  tính thời gian, định dạng số/thời gian và thông báo lỗi.

Mọi bài kiểm thử chỉ làm việc với `127.0.0.1`. Bài kiểm tra mục tiêu ngoài dải nội bộ
dùng `mock` để khẳng định không có kết nối nào được mở ra ngoài loopback. Thư mục tạm
của bài kiểm thử nằm trong `reports/` (đã bị `.gitignore` bỏ qua) và được xóa sau mỗi bài.

## Cách chạy

```powershell
# Quét một máy, dải cổng 1-1024 (cũng là mặc định khi chạy không tham số)
python main.py 127.0.0.1 --ports 1-1024

# Quét một dải CIDR (từ /18 đến /32)
python main.py 127.0.0.0/30 --ports 135,445

# Xuất báo cáo JSON (hoặc --format csv)
python main.py 127.0.0.1 --ports 1-1024 --output reports/single.json --format json
```

Lệnh giống nhau trên Windows, Linux và macOS. Xem đầy đủ các tham số ở bảng bên
dưới, và các ví dụ kèm kết quả ở mục [Ví dụ chạy và kết quả](#ví-dụ-chạy-và-kết-quả).

## Tham số

| Tham số | Mặc định | Mô tả |
| --- | --- | --- |
| `target` | `127.0.0.1` | Địa chỉ IPv4 hoặc dải CIDR từ /18 đến /32. |
| `--ports` | `1-1024` | Dải cổng hoặc danh sách cổng, ví dụ `1-1024`, `22,80,443`, `8000-8100`; tối đa `1-65535`. |
| `--timeout` | `1.0` | Thời gian chờ tối đa cho mỗi kết nối, tính bằng giây. |
| `--banner-timeout` | `0.5` | Thời gian chờ đọc banner cho mỗi cổng mở, tính bằng giây. |
| `--discovery-timeout` | `0.3` | Thời gian chờ dò host sống trong CIDR, tính bằng giây. |
| `--discovery-ports` | `22,80,135,443,445` | Cổng dùng để dò host sống trong CIDR. |
| `--workers` | `100` | Số luồng quét song song. |
| `--force` | không bật | Ghi đè file báo cáo đã tồn tại mà không hỏi. |
| `--yes` | không bật | Tự xác nhận mục tiêu ngoài dải nội bộ (vẫn in cảnh báo). |
| `--confirm-large-scan` | không bật | Tự xác nhận khi lần quét vượt mốc `500.000` lượt (vẫn in cảnh báo). |
| `--output` | không ghi file | Đường dẫn file báo cáo; nếu chỉ ghi tên file thì đặt trong `reports/`. |
| `--format` | `json` | Định dạng báo cáo: `json` hoặc `csv` (chỉ dùng khi có `--output`). |

Mẹo tinh chỉnh: tăng `--timeout` nếu mạng chậm; tăng `--banner-timeout` nếu dịch
vụ trả banner chậm; tăng `--discovery-timeout` nếu host phản hồi chậm; giảm
`--workers` nếu muốn hạn chế số kết nối đồng thời.

## Ví dụ chạy và kết quả

### Quét vài cổng cụ thể

Xem tên dịch vụ và banner:

```powershell
python main.py 127.0.0.1 --ports 135,445,5357
```

```text
Đang quét 127.0.0.1 với 3 cổng (timeout 1.0s, banner 0.5s, 100 luồng)...

Cổng mở trên 127.0.0.1:
  135/tcp  msrpc
  445/tcp  microsoft-ds
  5357/tcp  wsdapi  |  Server: Microsoft-HTTPAPI/2.0

Hoàn tất: 3 cổng mở trong 0.53 giây.
```

### Quét dải CIDR

```powershell
python main.py 127.0.0.0/30 --ports 1-1024
```

```text
Đang kiểm tra host sống trong 127.0.0.0/30 (2 host, cổng dò 22,80,135,443,445, timeout 0.3s)...
[1/2] 127.0.0.2: sống
[2/2] 127.0.0.1: sống

Tìm thấy 2/2 host sống trong 0.61 giây.

[1/2] Đang quét 127.0.0.1 (1024 cổng)...
Cổng mở trên 127.0.0.1:
  135/tcp  msrpc
  445/tcp  microsoft-ds
Hoàn tất host 127.0.0.1: 2 cổng mở trong 11.68 giây.

[2/2] Đang quét 127.0.0.2 (1024 cổng)...
Cổng mở trên 127.0.0.2:
  135/tcp  msrpc
  445/tcp  microsoft-ds
Hoàn tất host 127.0.0.2: 2 cổng mở trong 11.66 giây.

Tổng cộng: 2 host sống, 4 cổng mở.
```

Thứ tự các dòng tiến độ có thể khác thứ tự host vì các host được dò song song;
kết quả quét vẫn được in theo thứ tự địa chỉ.

### Xuất báo cáo JSON/CSV

Thư mục `reports/` được tạo tự động; nếu `--output` chỉ là tên file, báo cáo được
ghi vào `reports/`:

```powershell
python main.py 127.0.0.1 --ports 1-1024 --output reports/single.json --format json
python main.py 127.0.0.1 --ports 1-1024 --output reports/single.csv --format csv
python main.py 127.0.0.0/30 --ports 1-1024 --output reports/cidr.json --format json
```

Nội dung file mẫu xem ở mục [Xuất báo cáo JSON/CSV](#xuất-báo-cáo-jsoncsv).

### Một số tùy chọn khác

```powershell
# Quét vài cổng với timeout 1 giây
python main.py 192.168.1.10 --ports 22,80,443 --timeout 1

# Ghi đè báo cáo đã tồn tại mà không hỏi
python main.py 127.0.0.1 --ports 1-1024 --output reports/single.json --format json --force

# Tự xác nhận mục tiêu ngoài dải nội bộ (chỉ dùng khi có quyền quét)
python main.py 203.0.113.10 --ports 53 --yes

# Chỉ dò host sống qua cổng 135
python main.py 127.0.0.0/30 --ports 135,445 --discovery-ports 135
```

Khi chạy không tương tác (stdin không phải terminal), cần `--yes` để xác nhận mục
tiêu ngoài dải nội bộ và `--force` để ghi đè báo cáo.

## Cách hoạt động

Với mỗi cổng, chương trình mở một socket TCP và gọi `connect_ex()`. Hàm này
thực hiện TCP handshake (SYN → SYN/ACK → ACK) và trả về `0` khi kết nối thành
công — nghĩa là có tiến trình đang lắng nghe trên cổng đó. Các mã lỗi như
`ECONNREFUSED` (cổng đóng) hoặc timeout được coi là cổng không mở. Mỗi kết nối
có timeout riêng nên chương trình không bị treo khi gói tin bị drop.

## Quét CIDR và dò host sống

Khi nhận CIDR, chương trình dùng `ipaddress` mở rộng dải thành danh sách host
(bỏ địa chỉ mạng và broadcast khi có thể). CIDR có host bits sẽ được chuẩn hóa về
địa chỉ mạng trước khi quét. Dải lớn hơn `/18` bị từ chối ngay, không hỏi lại.

Trước khi quét toàn bộ dải cổng, chương trình thử TCP connect tới các cổng trong
`--discovery-ports` (mặc định `22,80,135,443,445`) với timeout ngắn
(`--discovery-timeout`) để loại nhanh các host không phản hồi; chỉ host sống mới
được quét kỹ. Cách này tránh quét toàn bộ cổng trên các địa chỉ không tồn tại, vốn
rất tốn thời gian. Tiến độ được in theo dạng `[đã xong/tổng] host`. Host chỉ mở
cổng nằm ngoài danh sách dò có thể bị bỏ qua.

Với một địa chỉ IP đơn lẻ, chương trình quét trực tiếp (không dò host) để không
bỏ sót host chỉ mở cổng không nằm trong danh sách dò.

## Nhận diện dịch vụ và banner

`services.py` ánh xạ các cổng phổ biến sang tên dịch vụ (ví dụ `22` → `ssh`,
`80` → `http`, `3306` → `mysql`). Với mỗi cổng mở, chương trình kết nối lại và
đọc tối đa 1024 byte đầu tiên với timeout ngắn (`--banner-timeout`). Với các cổng
HTTP phổ biến, chương trình gửi một yêu cầu `HEAD` tối giản để máy chủ trả về
header, thường có `Server:`. Banner sau đó được rút gọn thành một dòng ngắn.

Các cổng TLS như `443` hoặc `8443` thường không trả banner plaintext nên có thể
không có banner; tên dịch vụ vẫn được hiển thị theo bảng ánh xạ.

## Xuất báo cáo JSON/CSV

Phần ghi báo cáo nằm trong `report.py`. Thêm `--output` để ghi báo cáo; nếu không
có `--output`, chương trình chỉ in ra màn hình. `--format` chọn `json` (mặc định)
hoặc `csv`. Nếu `--output` chỉ là tên file, báo cáo được đặt trong `reports/` và
thư mục này được tạo tự động.

- JSON có `metadata` ở đầu (mục tiêu, dải cổng, tổng số cổng mở, thời gian quét
  `scan_duration_seconds`) và danh sách `results`.
- CSV có các cột `host,port,protocol,service,banner,scanned_at`; module `csv`
  tự quote banner có dấu phẩy, xuống dòng hoặc dấu nháy. File dùng UTF-8.
- Mỗi bản ghi có `scanned_at` theo ISO 8601; `banner` là `null` trong JSON hoặc
  trường rỗng trong CSV nếu không đọc được.
- Nếu file đã tồn tại, chương trình hỏi `Ghi đè? [y/N]`; dùng `--force` để ghi đè
  không hỏi. Khi stdin không phải terminal, không có `--force` thì báo lỗi và
  không ghi đè.
- Lỗi đường dẫn/không ghi được hoặc định dạng sai được báo rõ.

Ví dụ JSON:

```json
{
  "metadata": {
    "target": "127.0.0.1",
    "port_range": "1-1024",
    "total_open_ports": 2,
    "scan_duration_seconds": 11.688
  },
  "results": [
    {
      "host": "127.0.0.1",
      "port": 135,
      "protocol": "tcp",
      "service": "msrpc",
      "banner": null,
      "scanned_at": "2026-10-25T23:54:32+07:00"
    },
    {
      "host": "127.0.0.1",
      "port": 445,
      "protocol": "tcp",
      "service": "microsoft-ds",
      "banner": null,
      "scanned_at": "2026-10-25T23:54:32+07:00"
    }
  ]
}
```

Ví dụ CSV:

```csv
host,port,protocol,service,banner,scanned_at
127.0.0.1,135,tcp,msrpc,,2026-10-25T23:54:49+07:00
127.0.0.1,445,tcp,microsoft-ds,,2026-10-25T23:54:49+07:00
```

Với CIDR, tất cả host nằm trong cùng một mảng `results`; `metadata.target` là dải
CIDR. Thư mục `reports/` nằm trong `.gitignore` để kết quả quét (có thể chứa IP
nội bộ) không bị đưa lên GitHub.

## Giao diện web

Ngoài CLI còn có một giao diện web cục bộ, chỉ dùng thư viện chuẩn của Python và
một file HTML duy nhất (không CDN, không framework, không cần `pip install`).

Chạy:

```powershell
python web_server.py
```

Đổi cổng nếu 8000 đang bận:

```powershell
python web_server.py --port 8080
```

Sau đó mở địa chỉ mà chương trình in ra, ví dụ
[http://127.0.0.1:8000/](http://127.0.0.1:8000/).

Giao diện gồm:

- **Địa chỉ IP** và ô **CIDR, tùy chọn** (prefix `18`–`32`) nằm cùng hàng, ngăn bởi
  dấu `/`. Để trống prefix là quét một máy; điền prefix là quét cả dải. Ví dụ IP
  `192.168.1.10` với prefix `24` sẽ gửi lên `192.168.1.10/24` và server chuẩn hóa
  thành `192.168.1.0/24`.
- **Dòng xem trước** ngay dưới ô nhập, cập nhật khi gõ: `192.168.1.0/24 → 254 host,
  từ 192.168.1.1 đến 192.168.1.254 · ≈ 261.366 lượt quét, khoảng 43 phút`. Phần
  chuẩn hóa và đếm host được tính giống `ipaddress.ip_network(..., strict=False)`,
  phần ước tính giống công thức của server.
- **Dải cổng** kèm ba chip bấm một lần để điền: `Phổ biến`, `1-1024`, `Web`; nhận
  tới `1-65535`.
- **Tùy chọn nâng cao** (mặc định thu gọn, bấm để mở) gồm năm trường tương ứng tham
  số CLI. Mỗi trường có placeholder là giá trị mặc định của server:

  | Trường | Tham số API | Mặc định | Giới hạn server kiểm tra |
  | --- | --- | --- | --- |
  | Timeout mỗi kết nối (giây) | `timeout` | `1.0` | `0.05`–`10` |
  | Timeout đọc banner (giây) | `banner_timeout` | `0.5` | `0.05`–`10` |
  | Timeout dò host (giây) | `discovery_timeout` | `0.3` | `0.05`–`10` |
  | Cổng dò host sống | `discovery_ports` | `22,80,135,443,445` | dải cổng hợp lệ, tối đa 64 cổng |
  | Số luồng song song | `workers` | `100` | `1`–`100` |

  Để trống một trường nghĩa là dùng mặc định. Giao diện kiểm tra định dạng và khoảng
  để hỗ trợ nhập liệu, nhưng **server luôn kiểm tra lại** và là nơi quyết định.
- **Quét** / **Hủy quét**; nhấn Enter trong ô nhập cũng bắt đầu quét. Trong lúc
  chạy, các ô nhập, chip, tùy chọn nâng cao và nút Quét bị vô hiệu hóa, chỉ nút Hủy
  còn bật.
- **Cảnh báo quét lớn**: khi ước tính vượt `500.000` lượt, dòng xem trước chuyển
  sang hộp cảnh báo màu nổi bật kèm nút **Xác nhận quét lớn và bắt đầu**. Nếu vượt
  trần cứng `5.000.000` lượt, hộp cảnh báo nói rõ server sẽ từ chối và nút xác nhận
  không hiện.
- **Vùng tiến độ** (`aria-live="polite"`) hiển thị giai đoạn (dò host sống / quét
  cổng), lô đang chạy, số host đã xong, số cổng đã quét trên tổng số cổng của cả
  job và thời gian đã trôi qua.
- **Bảng kết quả** (host, cổng, dịch vụ, banner), sắp xếp theo địa chỉ IP bằng so
  sánh số rồi theo cổng; banner rỗng hiện `—`, banner dài được cắt gọn và hiện đầy
  đủ khi rê chuột. Bảng tự cập nhật sau mỗi lô, không chờ hết cả job. Nhãn "Kết quả
  một phần" hiện khi còn lô chưa chạy, khi bị hủy hoặc khi lỗi. Dòng dưới tiêu đề
  ghi lại đúng tham số của lần quét đã chạy (kể cả tùy chọn nâng cao khác mặc định),
  không lấy từ ô nhập hiện tại.
- Hai nút **tải JSON/CSV**, và giao diện tự chuyển màu theo chế độ tối của hệ điều
  hành (`prefers-color-scheme`) và co giãn trên màn hình hẹp.

Quét chạy ở thread nền; trang hỏi trạng thái định kỳ (polling, không dùng
WebSocket). Lỗi trả về từ server (400/403/409...) được hiện thành câu tiếng Việt
trên vùng trạng thái, không in JSON thô.

Kiểm tra IP và prefix ở phía giao diện chỉ để giúp nhập liệu nhanh; mọi giới hạn an
toàn vẫn do server quyết định.

### Quét theo lô

Mỗi job có thể nhận tối đa `65535` cổng. Server tự chia danh sách cổng (đã sắp xếp
và loại trùng) thành các **lô liên tiếp**, mỗi lô tối đa **2048** cổng, rồi quét
lần lượt từng lô:

- Ví dụ nhập `1-4096` sẽ chạy lô 1 (`1-2048`), hiện kết quả, rồi mới chạy lô 2
  (`2049-4096`).
- Với CIDR, bước **dò host sống chỉ chạy một lần** ở đầu; mỗi lô sau đó quét tất
  cả host sống.
- Sau mỗi lô, kết quả được gộp ngay vào job nên API polling trả về được **kết quả
  từng phần**. Kết quả luôn sắp xếp theo IP (so sánh số) rồi theo cổng.
- Hủy quét có hiệu lực cả giữa các lô lẫn trong lô đang chạy: job chuyển
  `cancelled`, kết quả của các lô đã xong được giữ nguyên và vẫn tải về được.

Hằng số kích thước lô nằm ở một chỗ duy nhất trong `web_server.py`
(`BATCH_SIZE = 2048`).

### API

| Phương thức | Đường dẫn | Mô tả |
| --- | --- | --- |
| `GET` | `/` | Trang giao diện, kèm token của phiên. |
| `POST` | `/api/scan` | Bắt đầu quét. Body JSON: `{"target": "...", "ports": "...", ...}`. Trả `202` kèm `id`, hoặc `202` kèm `confirmation_required: true` khi vượt mốc cảnh báo. Trường `target` là `"ip"` hoặc `"ip/prefix"`. |
| `GET` | `/api/scan/<id>` | Trạng thái, tiến độ và kết quả của một lần quét. |
| `POST` | `/api/scan/<id>/cancel` | Yêu cầu hủy lần quét đang chạy. |
| `GET` | `/api/scan/<id>/download?format=json\|csv` | Tải báo cáo, dùng lại `report.py`. Tải được cả khi job đang chạy hoặc đã bị hủy: chỉ trả những kết quả đã có. |

`GET /api/scan/<id>` trả về (giữ nguyên các trường cũ):

```json
{
  "id": "…",
  "target": "127.0.0.1",
  "ports": "1-4096",
  "status": "running",
  "phase": "scanning",
  "message": "[1/1] 127.0.0.1: 512/2048 cổng",
  "progress": { "done": 512, "total": 2048 },
  "batch": {
    "index": 1,
    "total": 2,
    "completed": 0,
    "port_range": "1-2048",
    "ports_done": 512,
    "ports_total": 4096
  },
  "started_at": "2026-10-26T12:00:00+07:00",
  "finished_at": null,
  "total_open_ports": 0,
  "results": [],
  "errors": [],
  "downloads": { "json": "…", "csv": "…" }
}
```

- `progress` là tiến độ **trong lô hiện tại**; `batch.ports_done / batch.ports_total`
  là tiến độ **của cả job** (giao diện dùng số này cho thanh tiến độ).
- `batch.completed` là số lô đã chạy xong.

Metadata trong file tải về gồm `target`, `port_range`, `total_open_ports`,
`scan_duration_seconds`, `batches_completed` và `batches_total`.

Mã lỗi: `400` dữ liệu sai / vượt giới hạn, `403` thiếu token / Host hoặc Origin lạ /
mục tiêu ngoài dải nội bộ, `404` id không tồn tại, `409` đang có lần quét khác chạy,
`413` body quá lớn. Lỗi luôn trả JSON `{"error": "..."}`, không lộ traceback.

### Ràng buộc an toàn của web server

- **Chỉ bind `127.0.0.1`.** Không có tham số nào đổi được địa chỉ bind, nên máy
  khác trong LAN không truy cập được và không dùng được máy bạn để quét.
- Kiểm tra **phía server**, không tin giao diện:
  - mục tiêu phải thuộc dải nội bộ (`10.0.0.0/8`, `172.16.0.0/12`,
    `192.168.0.0/16`, `127.0.0.0/8`), ngoài dải thì từ chối hẳn — trên web
    **không có** cơ chế xác nhận để quét mục tiêu ngoài;
  - CIDR lớn hơn `/18` bị từ chối;
  - tối đa `65535` cổng mỗi job, chia thành các lô `2048` cổng;
  - hai mốc giới hạn tổng lượt quét (xem mục "Hai mốc giới hạn" bên dưới);
  - tối đa `100` luồng; các timeout do server kiểm tra lại theo khoảng cho phép
    (`0.05`–`10` giây) dù giao diện gửi lên giá trị nào.
- Chống bị trang web khác lợi dụng: kiểm tra header `Host` (chỉ nhận
  `127.0.0.1:<cổng>` hoặc `localhost:<cổng>`), kiểm tra `Origin` với mọi request
  `POST`, và bắt buộc gửi token ngẫu nhiên sinh bằng `secrets` mỗi lần khởi động
  qua header `X-Scan-Token` (thiếu hoặc sai thì `403`). Token cũng được yêu cầu
  khi tải kết quả vì file chứa IP nội bộ.
- Trang gửi kèm `Content-Security-Policy` chặt, `X-Frame-Options: DENY` và
  `X-Content-Type-Options: nosniff`.
- Mọi dữ liệu hiển thị (banner, tên dịch vụ) được chèn bằng `textContent`, không
  bao giờ gán chuỗi HTML — banner do máy bị quét kiểm soát nên có thể chứa mã độc.

## Hai mốc giới hạn tổng lượt quét

Một lần quét được ước tính bằng **tổng số lượt quét**:

```text
trước khi dò host sống:  số host tối đa của dải × (số cổng quét + số cổng dò host)
sau khi dò host sống:    số host sống thực tế   ×  số cổng quét
```

Ví dụ: `/18` có 16382 host, nên `/18` × `1-65535` ước tính khoảng
`16382 × 65540 ≈ 1,07 tỷ` lượt. Một IP đơn không có bước dò host nên chỉ tính
`1 × số cổng`.

| Mốc | Giá trị | Hành vi |
| --- | --- | --- |
| Cảnh báo | `500.000` lượt | CLI in cảnh báo kèm ước tính thời gian và yêu cầu `--confirm-large-scan` (hoặc trả lời `y` khi chạy tương tác). Web trả `202` kèm `confirmation_required: true` và **chưa chạy gì**; phải gọi lại với `"confirm": true`. |
| Trần cứng | `5.000.000` lượt | Từ chối hẳn: CLI báo lỗi và thoát khác `0`, web trả `400`. **Không có cờ nào vượt qua**, và không mở kết nối nào trước khi từ chối. |

Thông báo khi vượt trần nêu rõ cách giảm: bớt số cổng hoặc thu nhỏ dải CIDR.
Ước tính thời gian dùng công thức `số lượt × timeout / số luồng`, tức trường hợp
xấu nhất khi mọi kết nối đều hết thời gian chờ.

> **Rủi ro khi quét dải lớn.** Quét vài chục nghìn host × vài chục nghìn cổng có
> thể làm chậm mạng của bạn, chiếm nhiều kết nối đồng thời, và rất dễ bị hệ thống
> an ninh mạng (firewall, IDS/IPS) phát hiện và chặn. Mốc `500.000` lượt ở mặc
> định đã tương đương khoảng `1,4 giờ`, còn `5.000.000` lượt khoảng `14 giờ` liên
> tục. Chỉ quét dải lớn trên mạng của chính bạn, và cân nhắc giảm số cổng hoặc
> thu nhỏ dải CIDR trước.

## An toàn

- Chỉ quét máy của bạn, mạng nhà bạn hoặc máy ảo lab.
- Nếu mục tiêu (IP hoặc CIDR) nằm ngoài các dải nội bộ (`10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`), chương trình sẽ cảnh báo
  và yêu cầu xác nhận trước khi quét; dùng `--yes` khi chạy không tương tác và
  chỉ khi bạn có quyền quét.
- Dải CIDR lớn hơn `/18` bị từ chối ngay, không hỏi lại.
- Lần quét vượt `500.000` lượt phải được xác nhận thêm (`--confirm-large-scan`
  trên CLI, hoặc bước xác nhận riêng trên web); vượt `5.000.000` lượt bị từ chối
  hẳn, không có cách vượt qua.
- Quét cổng trên hệ thống không thuộc quyền của bạn khi chưa được phép có thể vi phạm pháp luật.
- Web server chỉ lắng nghe trên `127.0.0.1`; nếu cần dùng từ máy khác thì phải tự
  cân nhắc rủi ro, không mở rộng địa chỉ bind trong công cụ này.
- Không có tính năng né tránh phát hiện (IDS evasion) hay quét tốc độ cao gây
  quá tải.