# Port Scanner

Công cụ quét cổng TCP dùng để học về mạng máy tính, đặc biệt là TCP handshake
và lập trình socket. Chương trình nhận một địa chỉ IPv4 hoặc một dải CIDR, kiểm
tra cổng nào đang mở bằng TCP connect, có timeout cho từng kết nối và quét song
song bằng thread pool. Với mỗi cổng mở, chương trình hiển thị tên dịch vụ và thử
đọc banner ngắn. Với CIDR, chương trình dò nhanh các host còn sống trước khi quét
cổng. Kết quả có thể xuất ra báo cáo JSON/CSV.

> Hiện tại: hỗ trợ IPv4/CIDR tối đa /24, nhận diện dịch vụ, banner, dò host sống và xuất báo cáo JSON/CSV. Bước 1–4 đã hoàn thành; chưa có giao diện web.

## Yêu cầu

- Python 3.11 trở lên.
- Chỉ dùng thư viện chuẩn của Python, không cần cài thêm gói.

## Cài đặt

```powershell
git clone https://github.com/howdion/Port-Scanner.git
cd Port-Scanner
py -3.12 -m venv .venv
```

Không cần cài thêm thư viện ngoài.

## Cấu trúc thư mục

```text
Port Scanner/
├── .gitignore
├── AGENTS.md          # hướng dẫn nội bộ (bị .gitignore bỏ qua)
├── main.py            # CLI, tham số, điều phối quét
├── README.md
├── report.py          # xuất báo cáo JSON/CSV
├── scanner.py         # quét cổng, dò host, đọc banner
├── services.py        # bảng ánh xạ cổng → tên dịch vụ
├── .venv/             # môi trường ảo (không commit)
├── __pycache__/       # cache Python (không commit)
└── reports/           # báo cáo sinh ra (không commit)
```

## Cách chạy

Trên Windows (dùng virtual environment của dự án):

```powershell
.venv\Scripts\python.exe main.py 127.0.0.1 --ports 1-1024
```

Quét vài cổng cụ thể để xem tên dịch vụ và banner:

```powershell
.venv\Scripts\python.exe main.py 127.0.0.1 --ports 135,445,5357
```

Quét một dải CIDR (tối đa /24):

```powershell
.venv\Scripts\python.exe main.py 127.0.0.0/30 --ports 1-1024
```

Xuất báo cáo JSON/CSV (thư mục `reports/` được tạo tự động):

```powershell
.venv\Scripts\python.exe main.py 127.0.0.1 --ports 1-1024 --output reports/single.json --format json
.venv\Scripts\python.exe main.py 127.0.0.1 --ports 1-1024 --output reports/single.csv --format csv
.venv\Scripts\python.exe main.py 127.0.0.0/30 --ports 1-1024 --output reports/cidr.json --format json
```

Nếu `--output` chỉ là tên file, báo cáo được ghi vào `reports/`.

Một số tùy chọn hữu ích:

```powershell
# Ghi đè báo cáo đã tồn tại mà không hỏi
.venv\Scripts\python.exe main.py 127.0.0.1 --ports 1-1024 --output reports/single.json --format json --force

# Tự xác nhận mục tiêu ngoài dải nội bộ (chỉ dùng khi có quyền quét)
.venv\Scripts\python.exe main.py 203.0.113.10 --ports 53 --yes

# Chỉ dò host sống qua cổng 135
.venv\Scripts\python.exe main.py 127.0.0.0/30 --ports 135,445 --discovery-ports 135
```

Khi chạy không tương tác (stdin không phải terminal), cần `--yes` để xác nhận mục
tiêu ngoài dải nội bộ và `--force` để ghi đè báo cáo.

Quét một vài cổng cụ thể với timeout 1 giây:

```powershell
.venv\Scripts\python.exe main.py 192.168.1.10 --ports 22,80,443 --timeout 1
```

Trên Linux/macOS:

```bash
.venv/bin/python main.py 127.0.0.1 --ports 1-1024
```

Chạy không tham số sẽ quét `127.0.0.1` với các cổng `1-1024`:

```powershell
.venv\Scripts\python.exe main.py
```

Tăng `--timeout` nếu mạng chậm; tăng `--banner-timeout` nếu dịch vụ trả banner
chậm; tăng `--discovery-timeout` nếu host phản hồi chậm; giảm `--workers` nếu
muốn hạn chế số kết nối đồng thời.

## Tham số

| Tham số | Mặc định | Mô tả |
| --- | --- | --- |
| `target` | `127.0.0.1` | Địa chỉ IPv4 hoặc dải CIDR tối đa /24. |
| `--ports` | `1-1024` | Dải cổng hoặc danh sách cổng, ví dụ `1-1024`, `22,80,443`, `8000-8100`. |
| `--timeout` | `1.0` | Thời gian chờ tối đa cho mỗi kết nối, tính bằng giây. |
| `--banner-timeout` | `0.5` | Thời gian chờ đọc banner cho mỗi cổng mở, tính bằng giây. |
| `--discovery-timeout` | `0.3` | Thời gian chờ dò host sống trong CIDR, tính bằng giây. |
| `--discovery-ports` | `22,80,135,443,445` | Cổng dùng để dò host sống trong CIDR. |
| `--workers` | `100` | Số luồng quét song song. |
| `--force` | không bật | Ghi đè file báo cáo đã tồn tại mà không hỏi. |
| `--yes` | không bật | Tự xác nhận mục tiêu ngoài dải nội bộ (vẫn in cảnh báo). |
| `--output` | không ghi file | Đường dẫn file báo cáo; nếu chỉ ghi tên file thì đặt trong `reports/`. |
| `--format` | `json` | Định dạng báo cáo: `json` hoặc `csv` (chỉ dùng khi có `--output`). |

## Ví dụ kết quả

```text
Đang quét 127.0.0.1 với 3 cổng (timeout 1.0s, banner 0.5s, 100 luồng)...

Cổng mở trên 127.0.0.1:
  135/tcp  msrpc
  445/tcp  microsoft-ds
  5357/tcp  wsdapi  |  Server: Microsoft-HTTPAPI/2.0

Hoàn tất: 3 cổng mở trong 0.53 giây.
```

## Ví dụ quét CIDR

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

## Cách hoạt động

Với mỗi cổng, chương trình mở một socket TCP và gọi `connect_ex()`. Hàm này
thực hiện TCP handshake (SYN → SYN/ACK → ACK) và trả về `0` khi kết nối thành
công — nghĩa là có tiến trình đang lắng nghe trên cổng đó. Các mã lỗi như
`ECONNREFUSED` (cổng đóng) hoặc timeout được coi là cổng không mở. Mỗi kết nối
có timeout riêng nên chương trình không bị treo khi gói tin bị drop.

## Quét CIDR và dò host sống

Khi nhận CIDR, chương trình dùng `ipaddress` mở rộng dải thành danh sách host
(bỏ địa chỉ mạng và broadcast khi có thể). CIDR có host bits sẽ được chuẩn hóa về
địa chỉ mạng trước khi quét. Dải lớn hơn `/24` bị từ chối ngay, không hỏi lại.

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

## An toàn

- Chỉ quét máy của bạn, mạng nhà bạn hoặc máy ảo lab.
- Nếu mục tiêu (IP hoặc CIDR) nằm ngoài các dải nội bộ (`10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`), chương trình sẽ cảnh báo
  và yêu cầu xác nhận trước khi quét; dùng `--yes` khi chạy không tương tác và
  chỉ khi bạn có quyền quét.
- Dải CIDR lớn hơn `/24` bị từ chối ngay, không hỏi lại.
- Quét cổng trên hệ thống không thuộc quyền của bạn khi chưa được phép có thể vi phạm pháp luật.
- Không có tính năng né tránh phát hiện (IDS evasion) hay quét tốc độ cao gây
  quá tải.
