# Port Scanner

Công cụ quét cổng TCP dùng để học về mạng máy tính, đặc biệt là TCP handshake
và lập trình socket. Hai giai đoạn được tách rời: `discover` dò host còn sống
trong một dải CIDR, `scan` kiểm tra cổng nào đang mở trên một IP hoặc trên danh
sách host bạn chọn. Mỗi kết nối có timeout riêng và được quét song song bằng
thread pool. Với mỗi cổng mở, chương trình hiển thị tên dịch vụ và thử đọc banner
ngắn. Kết quả có thể xuất ra báo cáo JSON/CSV.

> Hiện tại: CLI tách hai giai đoạn (`discover` / `scan`) cho IPv4 và CIDR từ `/18`
> đến `/32`, tối đa 65535 cổng mỗi lần quét, có hai mốc giới hạn cho **từng giai
> đoạn** (cảnh báo ở 500.000 và trần cứng 5.000.000 lượt), nhận diện dịch vụ,
> banner, xuất báo cáo JSON/CSV, kèm giao diện web cục bộ. Bước 1–5 đã hoàn thành.

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
│   ├── test_cli.py
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
  quét theo lô (chia lô, kết quả từng phần, hủy giữa các lô, giới hạn theo từng giai đoạn).
- `tests/test_batching.py`: hàm chia lô cổng, đếm host của mục tiêu, sắp xếp kết quả theo IP.
- `tests/test_limits.py`: hai mốc giới hạn cho từng giai đoạn, các hàm ước tính lượt và
  ước tính thời gian, định dạng số/thời gian, thông báo lỗi và giới hạn của CLI.
- `tests/test_cli.py`: hai subcommand `discover`/`scan`, `--hosts`/`--hosts-file`, từ
  chối CIDR trong `scan`, kiểm tra dải nội bộ từng host, và cách gọi cũ không có
  subcommand. Mọi kết nối đều được mock nên không chạm mạng.

Mọi bài kiểm thử chỉ làm việc với `127.0.0.1`. Bài kiểm tra mục tiêu ngoài dải nội bộ
dùng `mock` để khẳng định không có kết nối nào được mở ra ngoài loopback. Thư mục tạm
của bài kiểm thử nằm trong `reports/` (đã bị `.gitignore` bỏ qua) và được xóa sau mỗi bài.

## Cách chạy

Hai giai đoạn, hai lệnh. `discover` dò host sống, `scan` quét cổng trên danh sách
bạn chọn ở bước sau.

```powershell
# Giai đoạn 1: dò host sống trong CIDR, in danh sách và ghi file JSON
python main.py discover 192.168.1.0/24 --output hosts.json

# Giai đoạn 2: quét cổng trên danh sách host vừa dò được
python main.py scan --hosts-file hosts.json --ports 22,80,443

# Quét một IP đơn (không cần bước dò)
python main.py scan 127.0.0.1 --ports 1-1024

# Hoặc gõ host trực tiếp, phân cách bằng dấu phẩy
python main.py scan --hosts 192.168.1.5,192.168.1.9 --ports 22,80,443
```

Cách gọi cũ `python main.py 127.0.0.1 --ports 1-1024` (không có subcommand) vẫn
chạy như `scan` với một IP đơn. Nếu dùng cách cũ mà mục tiêu là CIDR, chương trình
từ chối và nhắc chạy `discover` trước.

Lệnh giống nhau trên Windows, Linux và macOS. Xem đầy đủ các tham số ở bảng bên
dưới, và các ví dụ kèm kết quả ở mục [Ví dụ chạy và kết quả](#ví-dụ-chạy-và-kết-quả).

## Tham số

### `main.py discover <CIDR>`

Chỉ dò host sống, **không** quét cổng.

| Tham số | Mặc định | Mô tả |
| --- | --- | --- |
| `CIDR` | bắt buộc | Dải CIDR từ /18 đến /32, ví dụ `192.168.1.0/24`. |
| `--discovery-ports` | `22,80,135,443,445` | Cổng dùng để dò host sống. |
| `--discovery-timeout` | `0.3` | Thời gian chờ mỗi lần thử khi dò, tính bằng giây. |
| `--concurrency` | `100` | Số luồng dò song song. |
| `--output` | không ghi file | Ghi JSON `{cidr, discovery_ports, discovered_at, live_hosts}`; nếu chỉ ghi tên file thì đặt trong `reports/`. |
| `--force` | không bật | Ghi đè file kết quả đã tồn tại mà không hỏi. |
| `--yes` | không bật | Tự xác nhận dò CIDR ngoài dải nội bộ (vẫn in cảnh báo). |
| `--confirm-large-scan` | không bật | Tự xác nhận khi giai đoạn dò vượt mốc `500.000` lượt. |

### `main.py scan [IP] [--hosts ...] [--hosts-file ...]`

Quét cổng trên một IP đơn **hoặc** danh sách host. Chỉ được chọn một trong ba
nguồn host: `IP`, `--hosts`, `--hosts-file`.

| Tham số | Mặc định | Mô tả |
| --- | --- | --- |
| `IP` | không có | Một địa chỉ IPv4 đơn. Không nhận CIDR. |
| `--hosts` | không có | Danh sách host phân cách bằng dấu phẩy, ví dụ `192.168.1.5,192.168.1.9`. |
| `--hosts-file` | không có | File JSON do `discover --output` tạo ra. |
| `--ports` | `1-1024` | Dải cổng hoặc danh sách cổng, ví dụ `1-1024`, `22,80,443`, `8000-8100`; tối đa `1-65535`. |
| `--timeout` | `1.0` | Thời gian chờ tối đa cho mỗi kết nối, tính bằng giây. |
| `--banner-timeout` | `0.5` | Thời gian chờ đọc banner cho mỗi cổng mở, tính bằng giây. |
| `--workers` | `100` | Số luồng quét song song. |
| `--force` | không bật | Ghi đè file báo cáo đã tồn tại mà không hỏi. |
| `--yes` | không bật | Tự xác nhận mục tiêu ngoài dải nội bộ (vẫn in cảnh báo). |
| `--confirm-large-scan` | không bật | Tự xác nhận khi giai đoạn quét vượt mốc `500.000` lượt. |
| `--output` | không ghi file | Đường dẫn file báo cáo; nếu chỉ ghi tên file thì đặt trong `reports/`. |
| `--format` | `json` | Định dạng báo cáo: `json` hoặc `csv` (chỉ dùng khi có `--output`). |

Mẹo tinh chỉnh: tăng `--timeout` nếu mạng chậm; tăng `--banner-timeout` nếu dịch
vụ trả banner chậm; tăng `--discovery-timeout` nếu host phản hồi chậm; giảm
`--workers`/`--concurrency` nếu muốn hạn chế số kết nối đồng thời.

## Ví dụ chạy và kết quả

### Quét vài cổng cụ thể

Xem tên dịch vụ và banner:

```powershell
python main.py scan 127.0.0.1 --ports 135,445,5357
```

```text
Đang quét 127.0.0.1 với 3 cổng (timeout 1.0s, banner 0.5s, 100 luồng)...

Cổng mở trên 127.0.0.1:
  135/tcp  msrpc
  445/tcp  microsoft-ds
  5357/tcp  wsdapi  |  Server: Microsoft-HTTPAPI/2.0

Hoàn tất: 3 cổng mở trong 0.53 giây.
```

### Dò host sống rồi quét cổng trên host đã chọn

Hai lệnh, hai giai đoạn. Trước hết dò host sống và lưu lại:

```powershell
python main.py discover 127.0.0.0/30 --discovery-ports 135,445 --output hosts.json
```

```text
Đang dò host sống trong 127.0.0.0/30 (2 host, cổng dò 135,445, timeout 0.3s, 100 luồng)...
[1/2] 127.0.0.2: sống
[2/2] 127.0.0.1: sống

Tìm thấy 2/2 host sống trong 0.01 giây.
Danh sách host sống:
  127.0.0.1
  127.0.0.2
Đã ghi danh sách host sống: reports\hosts.json
Dùng lại bằng: main.py scan --hosts-file reports\hosts.json --ports <dải cổng>
```

File `reports/hosts.json` có dạng:

```json
{
  "cidr": "127.0.0.0/30",
  "discovery_ports": "135,445",
  "discovered_at": "2026-10-26T22:51:12+07:00",
  "live_hosts": ["127.0.0.1", "127.0.0.2"]
}
```

Sau khi xem danh sách (và có thể sửa bớt host), quét cổng ở bước riêng:

```powershell
python main.py scan --hosts-file reports/hosts.json --ports 135,445 --timeout 0.3
```

```text
Đang quét 2 host với 2 cổng (timeout 0.3s, banner 0.5s, 100 luồng)...

[1/2] Đang quét 127.0.0.1 (2 cổng)...
Cổng mở trên 127.0.0.1:
  135/tcp  msrpc
  445/tcp  microsoft-ds
Hoàn tất host 127.0.0.1: 2 cổng mở trong 0.53 giây.

[2/2] Đang quét 127.0.0.2 (2 cổng)...
Cổng mở trên 127.0.0.2:
  135/tcp  msrpc
  445/tcp  microsoft-ds
Hoàn tất host 127.0.0.2: 2 cổng mở trong 0.52 giây.

Tổng cộng: 2 host, 4 cổng mở.
```

Thứ tự các dòng tiến độ khi dò có thể khác thứ tự host vì các host được dò song
song; danh sách host sống và kết quả quét vẫn được in theo thứ tự địa chỉ.

### Xuất báo cáo JSON/CSV

Thư mục `reports/` được tạo tự động; nếu `--output` chỉ là tên file, báo cáo được
ghi vào `reports/`:

```powershell
python main.py scan 127.0.0.1 --ports 1-1024 --output single.json --format json
python main.py scan 127.0.0.1 --ports 1-1024 --output single.csv --format csv
python main.py scan --hosts-file reports/hosts.json --ports 1-1024 --output cidr.json
```

Nội dung file mẫu xem ở mục [Xuất báo cáo JSON/CSV](#xuất-báo-cáo-jsoncsv).

### Một số tùy chọn khác

```powershell
# Quét vài cổng với timeout 1 giây
python main.py scan 192.168.1.10 --ports 22,80,443 --timeout 1

# Ghi đè báo cáo đã tồn tại mà không hỏi
python main.py scan 127.0.0.1 --ports 1-1024 --output single.json --force

# Tự xác nhận mục tiêu ngoài dải nội bộ (chỉ dùng khi có quyền quét)
python main.py scan 203.0.113.10 --ports 53 --yes

# Dò host sống chỉ qua cổng 135, rồi quét danh sách gõ tay
python main.py discover 127.0.0.0/30 --discovery-ports 135
python main.py scan --hosts 127.0.0.1,127.0.0.2 --ports 135,445
```

Khi chạy không tương tác (stdin không phải terminal), cần `--yes` để xác nhận mục
tiêu ngoài dải nội bộ, `--force` để ghi đè file, và `--confirm-large-scan` khi một
giai đoạn vượt mốc cảnh báo.

## Cách hoạt động

Với mỗi cổng, chương trình mở một socket TCP và gọi `connect_ex()`. Hàm này
thực hiện TCP handshake (SYN → SYN/ACK → ACK) và trả về `0` khi kết nối thành
công — nghĩa là có tiến trình đang lắng nghe trên cổng đó. Các mã lỗi như
`ECONNREFUSED` (cổng đóng) hoặc timeout được coi là cổng không mở. Mỗi kết nối
có timeout riêng nên chương trình không bị treo khi gói tin bị drop.

## Dò host sống và quét cổng là hai bước tách rời

CLI cố tình **không** tự chạy nối tiếp hai giai đoạn. Lý do: giới hạn của giai đoạn
quét cổng phải dựa trên số host thật. Nếu tự dò rồi tự quét, lúc kiểm tra giới hạn
chương trình chỉ biết số host tối đa của dải nên phải ước tính trường hợp xấu nhất
(mọi host đều sống), khiến con số luôn cao hơn thực tế rất nhiều.

Quy trình hai bước:

1. `main.py discover <CIDR>` mở rộng dải bằng `ipaddress` (bỏ địa chỉ mạng và
   broadcast khi có thể, chuẩn hóa host bits về địa chỉ mạng), rồi thử TCP connect
   tới các cổng trong `--discovery-ports` với timeout ngắn `--discovery-timeout`.
   Host phản hồi ở ít nhất một cổng được coi là sống. Tiến độ in theo dạng
   `[đã xong/tổng] host`. Dải lớn hơn `/18` bị từ chối ngay.
2. `main.py scan --hosts-file <file>` hoặc `--hosts ip1,ip2` quét cổng trên đúng
   danh sách đó. Số host dùng để kiểm tra giới hạn là **số phần tử thật** của danh
   sách, nên không còn phép ước tính nào.

Host chỉ mở cổng nằm ngoài danh sách dò có thể bị `discover` bỏ qua — đó là lý do
danh sách host được ghi ra file để bạn xem và sửa trước khi quét. Với một địa chỉ IP
đơn, `scan` quét trực tiếp (không dò) để không bỏ sót trường hợp đó.

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

- JSON có `metadata` ở đầu và danh sách `results`. `metadata` gồm:
  - `target` — nhãn hiển thị: địa chỉ IP khi quét một host, hoặc `"N host"` khi
    quét danh sách (giữ trường cũ để không phá định dạng đang dùng);
  - `target_hosts` — **danh sách host thật đã quét** (mới), ví dụ
    `["127.0.0.1", "127.0.0.2"]`, đúng thứ tự gửi lên, không trùng;
  - `hosts_count` — số host trong `target_hosts`;
  - `port_range`, `total_open_ports`, `scan_duration_seconds` như cũ; bản tải từ
    web có thêm `batches_completed` và `batches_total`.
- CSV có các cột `host,port,protocol,service,banner,scanned_at`; module `csv`
  tự quote banner có dấu phẩy, xuống dòng hoặc dấu nháy. File dùng UTF-8. CSV không
  có phần metadata, chỉ có các dòng kết quả.
- Mỗi bản ghi có `scanned_at` theo ISO 8601; `banner` là `null` trong JSON hoặc
  trường rỗng trong CSV nếu không đọc được.
- Nếu file đã tồn tại, chương trình hỏi `Ghi đè? [y/N]`; dùng `--force` để ghi đè
  không hỏi. Khi stdin không phải terminal, không có `--force` thì báo lỗi và
  không ghi đè.
- Lỗi đường dẫn/không ghi được hoặc định dạng sai được báo rõ.

Ví dụ JSON (quét một host):

```json
{
  "metadata": {
    "target": "127.0.0.1",
    "target_hosts": ["127.0.0.1"],
    "hosts_count": 1,
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

Khi quét nhiều host (qua `--hosts` hoặc `--hosts-file`), tất cả host nằm trong cùng
một mảng `results`; `metadata.target` là nhãn `"N host"`, còn `metadata.target_hosts`
liệt kê đầy đủ các host đã quét. Thư mục `reports/` nằm trong `.gitignore` để kết quả
quét (có thể chứa IP nội bộ) không bị đưa lên GitHub.

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

Trang có **hai khối độc lập**, xếp theo đúng thứ tự công việc:

### Khối 1 — Dò host sống

- Ô **Dải CIDR** (prefix `18`–`32`), ví dụ `192.168.1.0/24`. Dòng xem trước hiện
  dải đã chuẩn hóa và số host, kèm **một dòng ước tính của riêng giai đoạn dò**:
  `Lượt dò (ước tính): 1.270 (254 host × 5 cổng dò) · khoảng 4 giây`. Dòng này tự
  đổi màu khi vượt mốc (vàng: cần xác nhận, đỏ: vượt trần cứng).
- **Tùy chọn nâng cao** (thu gọn): `discovery_ports`, `discovery_timeout`,
  `concurrency` — placeholder là giá trị mặc định của server.
- Nút **Dò host sống** / **Hủy dò**, thanh tiến độ và thời gian chạy riêng.
- Kết quả là **bảng danh sách host sống**, mỗi dòng có checkbox, kèm hai nút
  **Chọn tất cả** / **Bỏ chọn tất cả** và dòng "Đã chọn N/M host sống". Mặc định
  chọn hết các host vừa dò được.

### Khối 2 — Quét cổng

- Ô **Host cần quét** luôn có sẵn: một IP hoặc danh sách IP cách nhau bằng dấu phẩy
  (`10.0.0.5,10.0.0.9`), dùng độc lập không cần qua bước dò. Không nhận CIDR.
- Khi bảng dò có host, dòng "Đã chọn N/M host sống" và nút **Dùng host đã chọn**
  xuất hiện: bấm nút này thì khối quét dùng đúng danh sách đang tick trong bảng
  (gõ tay vào ô host sẽ quay lại chế độ nhập tay).
- **Dải cổng** kèm ba chip `Phổ biến`, `1-1024`, `Web`; nhận tới `1-65535`.
- **Tùy chọn nâng cao** (thu gọn): `timeout`, `banner_timeout`, `concurrency`.

  | Trường | Tham số API | Mặc định | Giới hạn server kiểm tra |
  | --- | --- | --- | --- |
  | Timeout mỗi kết nối (giây) | `timeout` | `1.0` | `0.05`–`10` |
  | Timeout đọc banner (giây) | `banner_timeout` | `0.5` | `0.05`–`10` |
  | Timeout dò host (giây) | `discovery_timeout` | `0.3` | `0.05`–`10` |
  | Cổng dò host sống | `discovery_ports` | `22,80,135,443,445` | dải cổng hợp lệ, tối đa 64 cổng |
  | Số luồng song song | `concurrency` | `100` | `1`–`100` |

  Để trống một trường nghĩa là dùng mặc định. Giao diện kiểm tra định dạng và khoảng
  để hỗ trợ nhập liệu, nhưng **server luôn kiểm tra lại** và là nơi quyết định.
- Dòng ước tính của khối này dùng **số host thật** đang chọn/nhập:
  `Lượt quét cổng (số host thật): 2.048 (2 host × 1.024 cổng) · khoảng 20 giây`.
- Nút **Quét** / **Hủy quét**, thanh tiến độ, **bảng kết quả** (host, cổng, dịch vụ,
  banner) và hai nút tải **JSON/CSV** — giống khối kết quả trước đây.

Hai khối chạy hoàn toàn độc lập: có thể quét cổng nhiều lần với các lựa chọn host
khác nhau từ **cùng một lần dò**, không phải dò lại. Cảnh báo quét lớn hiện riêng
trong từng khối và nêu rõ giai đoạn nào vượt mốc.

Quét chạy ở thread nền; trang hỏi trạng thái định kỳ (polling, không dùng
WebSocket). Lỗi trả về từ server (400/403/409/413...) được hiện thành câu tiếng Việt
trên vùng trạng thái của khối tương ứng, không in JSON thô.

Kiểm tra phía giao diện chỉ để giúp nhập liệu nhanh; mọi giới hạn an toàn vẫn do
server quyết định. Trang không dùng `innerHTML` hay bất kỳ cách chèn HTML nào: mọi
dữ liệu từ server (host, banner) đều vào DOM bằng `textContent`.

### Quét theo lô

Mỗi job có thể nhận tối đa `65535` cổng. Server tự chia danh sách cổng (đã sắp xếp
và loại trùng) thành các **lô liên tiếp**, mỗi lô tối đa **2048** cổng, rồi quét
lần lượt từng lô:

- Ví dụ nhập `1-4096` sẽ chạy lô 1 (`1-2048`), hiện kết quả, rồi mới chạy lô 2
  (`2049-4096`).
- Job `scan` chỉ quét cổng trên danh sách host client gửi lên; bước dò host sống
  là **job `discover` riêng**, không tự chạy kèm.
- Sau mỗi lô, kết quả được gộp ngay vào job nên API polling trả về được **kết quả
  từng phần**. Kết quả luôn sắp xếp theo IP (so sánh số) rồi theo cổng.
- Hủy quét có hiệu lực cả giữa các lô lẫn trong lô đang chạy: job chuyển
  `cancelled`, kết quả của các lô đã xong được giữ nguyên và vẫn tải về được.

Hằng số kích thước lô nằm ở một chỗ duy nhất trong `web_server.py`
(`BATCH_SIZE = 2048`).

### API

Hai loại job, hai nhóm endpoint. Mỗi job có `id` riêng và vòng đời riêng; không
job nào tự chuyển từ giai đoạn này sang giai đoạn kia.

| Phương thức | Đường dẫn | Mô tả |
| --- | --- | --- |
| `GET` | `/` | Trang giao diện, kèm token của phiên. |
| `POST` | `/api/discover` | Dò host sống trong một CIDR. Body: `{"cidr": "…", "discovery_ports"?, "discovery_timeout"?, "concurrency"?, "confirm"?}`. Trả `202` kèm `id`, hoặc `202` kèm `confirmation_required: true` khi vượt mốc cảnh báo. |
| `GET` | `/api/discover/<id>` | Trạng thái, tiến độ và `live_hosts` khi xong. |
| `POST` | `/api/discover/<id>/cancel` | Yêu cầu hủy lần dò đang chạy. |
| `POST` | `/api/scan` | Quét cổng trên danh sách host. Body: `{"hosts": ["127.0.0.1"], "ports": "1-1024", "timeout"?, "banner_timeout"?, "concurrency"?, "confirm"?}`. Trả `202` kèm `id`, hoặc `202` kèm `confirmation_required: true`. |
| `GET` | `/api/scan/<id>` | Trạng thái, tiến độ và kết quả của một lần quét. |
| `POST` | `/api/scan/<id>/cancel` | Yêu cầu hủy lần quét đang chạy. |
| `GET` | `/api/scan/<id>/download?format=json\|csv` | Tải báo cáo, dùng lại `report.py`. Tải được cả khi job đang chạy hoặc đã bị hủy: chỉ trả những kết quả đã có. |

`hosts` là danh sách IPv4 tường minh, **không nhận CIDR**. Muốn quét theo dải thì
gọi `/api/discover` trước rồi dùng `live_hosts` trả về. Quét một IP chỉ cần
`"hosts": ["127.0.0.1"]`, không phải qua `discover`.

Một lượt hai bước, gọi bằng `curl` (thay `TOKEN` bằng token trong trang):

```powershell
# Bước 1: dò host sống
curl.exe -s -X POST http://127.0.0.1:8000/api/discover `
  -H "X-Scan-Token: TOKEN" -H "Content-Type: application/json" `
  -d '{\"cidr\":\"192.168.1.0/24\",\"discovery_ports\":\"22,80,135,443,445\"}'

# Chờ tới khi status = done, rồi lấy danh sách trong trường live_hosts:
curl.exe -s http://127.0.0.1:8000/api/discover/<id>

# Bước 2: quét cổng trên những host bạn chọn
curl.exe -s -X POST http://127.0.0.1:8000/api/scan `
  -H "X-Scan-Token: TOKEN" -H "Content-Type: application/json" `
  -d '{\"hosts\":[\"192.168.1.5\",\"192.168.1.9\"],\"ports\":\"22,80,443\"}'
```

`GET /api/discover/<id>` trả về:

```json
{
  "id": "…",
  "kind": "discover",
  "cidr": "192.168.1.0/24",
  "status": "done",
  "phase": "discovery",
  "message": "Hoàn tất: 12/254 host sống.",
  "hosts_total": 254,
  "live_hosts": ["192.168.1.5", "192.168.1.9"],
  "total_live_hosts": 2,
  "progress": { "done": 254, "total": 254 },
  "params": {
    "discovery_ports": "22,80,135,443,445",
    "discovery_timeout": 0.3,
    "concurrency": 100
  },
  "started_at": "2026-10-26T12:00:00+07:00",
  "finished_at": "2026-10-26T12:00:04+07:00"
}
```

`GET /api/scan/<id>` trả về:

```json
{
  "id": "…",
  "kind": "scan",
  "target": "127.0.0.1",
  "hosts": ["127.0.0.1"],
  "host_count": 1,
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
  "params": { "timeout": 1.0, "banner_timeout": 0.5, "concurrency": 100 },
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
- `target` là nhãn hiển thị: một IP khi `hosts` có đúng một phần tử, ngược lại
  `"N host"`.

Metadata trong file tải về gồm `target` (nhãn), `target_hosts` (danh sách host thật),
`hosts_count`, `port_range`, `total_open_ports`, `scan_duration_seconds`,
`batches_completed` và `batches_total`.

**Chạy đồng thời.** Mỗi loại job chỉ cho một job chạy tại một thời điểm: gọi
`/api/scan` khi đang có job scan sẽ nhận `409`, tương tự với `/api/discover`.
Hai loại **độc lập** nên một job discover và một job scan có thể chạy cùng lúc.

Body JSON tối đa **1 MiB**, đủ cho danh sách host của một lần dò `/18` (tối đa
16.382 host, khoảng 300 KB); lớn hơn thì trả `413`.

Mã lỗi: `400` dữ liệu sai / vượt giới hạn, `403` thiếu token / Host hoặc Origin lạ /
CIDR hoặc host ngoài dải nội bộ, `404` id không tồn tại hoặc sai loại job, `409`
đang có job cùng loại chạy, `413` body quá lớn. Lỗi luôn trả JSON `{"error": "..."}`,
không lộ traceback.

### Ràng buộc an toàn của web server

- **Chỉ bind `127.0.0.1`.** Không có tham số nào đổi được địa chỉ bind, nên máy
  khác trong LAN không truy cập được và không dùng được máy bạn để quét.
- Kiểm tra **phía server**, không tin giao diện:
  - CIDR của `/api/discover` phải thuộc dải nội bộ (`10.0.0.0/8`,
    `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`), ngoài dải thì từ chối hẳn;
  - **từng host** trong `hosts` của `/api/scan` cũng bị kiểm tra như vậy — trên web
    **không có** cơ chế xác nhận để quét mục tiêu ngoài;
  - CIDR lớn hơn `/18` bị từ chối;
  - tối đa `65535` cổng mỗi job, chia thành các lô `2048` cổng;
  - hai mốc giới hạn áp dụng riêng cho từng loại job (xem mục "Hai mốc giới hạn
    cho từng giai đoạn" bên dưới);
  - tối đa `100` luồng; các timeout do server kiểm tra lại theo khoảng cho phép
    (`0.05`–`10` giây) dù giao diện gửi lên giá trị nào;
  - mỗi loại job chỉ một cái chạy tại một thời điểm.
- Chống bị trang web khác lợi dụng: kiểm tra header `Host` (chỉ nhận
  `127.0.0.1:<cổng>` hoặc `localhost:<cổng>`), kiểm tra `Origin` với mọi request
  `POST`, và bắt buộc gửi token ngẫu nhiên sinh bằng `secrets` mỗi lần khởi động
  qua header `X-Scan-Token` (thiếu hoặc sai thì `403`). Token cũng được yêu cầu
  khi tải kết quả vì file chứa IP nội bộ.
- Trang gửi kèm `Content-Security-Policy` chặt, `X-Frame-Options: DENY` và
  `X-Content-Type-Options: nosniff`.
- Mọi dữ liệu hiển thị (banner, tên dịch vụ) được chèn bằng `textContent`, không
  bao giờ gán chuỗi HTML — banner do máy bị quét kiểm soát nên có thể chứa mã độc.

## Hai mốc giới hạn cho từng giai đoạn

Mỗi lệnh chỉ chạy **một** giai đoạn, và giới hạn được tính bằng số liệu thật của
chính giai đoạn đó:

```text
discover:  số host tối đa của dải CIDR × số cổng dò host
scan:      số host trong danh sách      × số cổng quét
```

Không có phép cộng hai giai đoạn, và ở `scan` cũng không còn phép ước tính "xấu
nhất": danh sách host đã biết chắc chắn nên con số là thật. Một IP đơn chỉ có giai
đoạn quét với số host bằng `1` (`1 × số cổng`).

Ví dụ với `127.0.0.0/18` và 5 cổng dò mặc định:

- `main.py discover 127.0.0.0/18` → `16382 × 5 = 81.910` lượt, dưới mốc cảnh báo
  nên chạy bình thường;
- sau khi dò xong, nếu danh sách chỉ có 12 host thì `main.py scan --hosts-file ...`
  với `1-1024` chỉ tính `12 × 1024 = 12.288` lượt — thay vì `16.775.168` lượt của
  cách ước tính theo số host tối đa.

| Mốc | Giá trị | Hành vi cho **mỗi giai đoạn** |
| --- | --- | --- |
| Cảnh báo | `500.000` lượt | CLI in cảnh báo nêu tên giai đoạn, kèm ước tính thời gian và yêu cầu `--confirm-large-scan` (hoặc trả lời `y` khi chạy tương tác). Web trả `202` kèm `confirmation_required: true` và danh sách `stages` vượt mốc, **chưa chạy gì**; phải gọi lại với `"confirm": true`. |
| Trần cứng | `5.000.000` lượt | Từ chối hẳn: CLI báo lỗi nêu tên giai đoạn và thoát khác `0`, web trả `400`. **Không có cờ nào vượt qua**, và không mở kết nối nào trước khi từ chối. |

Thông báo khi vượt trần nêu rõ cách giảm: bớt số cổng, bớt cổng dò host, hoặc thu nhỏ
dải CIDR (với `scan` là bớt host trong danh sách). Ước tính thời gian dùng công thức
`số lượt × timeout / số luồng`, tức trường hợp xấu nhất khi mọi kết nối đều hết thời
gian chờ.

> **Rủi ro khi quét dải lớn.** Quét vài chục nghìn host × vài chục nghìn cổng có
> thể làm chậm mạng của bạn, chiếm nhiều kết nối đồng thời, và rất dễ bị hệ thống
> an ninh mạng (firewall, IDS/IPS) phát hiện và chặn. Mốc `500.000` lượt ở mặc
> định đã tương đương khoảng `1,4 giờ`, còn `5.000.000` lượt khoảng `14 giờ` liên
> tục. Chỉ quét dải lớn trên mạng của chính bạn, và cân nhắc giảm số cổng hoặc
> thu nhỏ dải CIDR trước.

## An toàn

- Chỉ quét máy của bạn, mạng nhà bạn hoặc máy ảo lab.
- Nếu mục tiêu (IP của `scan` hoặc CIDR của `discover`) nằm ngoài các dải nội bộ
  (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`), chương trình
  sẽ cảnh báo và yêu cầu xác nhận trước khi chạy; dùng `--yes` khi chạy không
  tương tác và chỉ khi bạn có quyền quét.
- Mọi host trong `--hosts` và `--hosts-file` bị kiểm tra **từng địa chỉ**: host
  không phải IPv4 hợp lệ hoặc nằm ngoài dải nội bộ bị từ chối hẳn, không có cờ nào
  bỏ qua.
- Dải CIDR lớn hơn `/18` bị từ chối ngay, không hỏi lại.
- Mỗi giai đoạn vượt `500.000` lượt phải được xác nhận thêm (`--confirm-large-scan`
  trên CLI, hoặc bước xác nhận riêng trên web); giai đoạn nào vượt `5.000.000` lượt
  bị từ chối hẳn, không có cách vượt qua.
- Quét cổng trên hệ thống không thuộc quyền của bạn khi chưa được phép có thể vi phạm pháp luật.
- Web server chỉ lắng nghe trên `127.0.0.1`; nếu cần dùng từ máy khác thì phải tự
  cân nhắc rủi ro, không mở rộng địa chỉ bind trong công cụ này.
- Không có tính năng né tránh phát hiện (IDS evasion) hay quét tốc độ cao gây
  quá tải.