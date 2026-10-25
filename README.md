# Port Scanner

Công cụ quét cổng TCP dùng để học về mạng máy tính, đặc biệt là TCP handshake
và lập trình socket. Chương trình nhận một địa chỉ IPv4 và một dải cổng, kiểm tra
cổng nào đang mở bằng TCP connect, có timeout cho từng kết nối và quét song song
bằng thread pool. Với mỗi cổng mở, chương trình hiển thị tên dịch vụ và thử đọc
banner ngắn.

> Phạm vi hiện tại: một địa chỉ IPv4, một dải cổng; nhận diện dịch vụ theo cổng
> và đọc banner ngắn. Chưa hỗ trợ tên miền, dải CIDR hay xuất báo cáo.

> Trạng thái: Bước 1 và 2 đã hoàn thành.

## Yêu cầu

- Python 3.11 trở lên.
- Chỉ dùng thư viện chuẩn của Python, không cần cài thêm gói.

## Cách chạy

Trên Windows (dùng virtual environment của dự án):

```powershell
.venv\Scripts\python.exe main.py 127.0.0.1 --ports 1-1024
```

Quét các cổng HTTP để xem banner:

```powershell
.venv\Scripts\python.exe main.py 127.0.0.1 --ports 135,445,5357
```

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
chậm; giảm `--workers` nếu muốn hạn chế số kết nối đồng thời.

## Tham số

| Tham số | Mặc định | Mô tả |
| --- | --- | --- |
| `target` | `127.0.0.1` | Địa chỉ IPv4 cần quét. |
| `--ports` | `1-1024` | Dải cổng hoặc danh sách cổng, ví dụ `1-1024`, `22,80,443`, `8000-8100`. |
| `--timeout` | `1.0` | Thời gian chờ tối đa cho mỗi kết nối, tính bằng giây. |
| `--banner-timeout` | `0.5` | Thời gian chờ đọc banner cho mỗi cổng mở, tính bằng giây. |
| `--workers` | `100` | Số luồng quét song song. |

## Ví dụ kết quả

```text
Đang quét 127.0.0.1 với 3 cổng (timeout 1.0s, banner 0.5s, 100 luồng)...

Cổng mở trên 127.0.0.1:
  135/tcp  msrpc
  445/tcp  microsoft-ds
  5357/tcp  http-alt  |  Server: Microsoft-HTTPAPI/2.0

Hoàn tất: 3 cổng mở trong 0.53 giây.
```

## Cách hoạt động

Với mỗi cổng, chương trình mở một socket TCP và gọi `connect_ex()`. Hàm này
thực hiện TCP handshake (SYN → SYN/ACK → ACK) và trả về `0` khi kết nối thành
công — nghĩa là có tiến trình đang lắng nghe trên cổng đó. Các mã lỗi như
`ECONNREFUSED` (cổng đóng) hoặc timeout được coi là cổng không mở. Mỗi kết nối
có timeout riêng nên chương trình không bị treo khi gói tin bị drop.

## Nhận diện dịch vụ và banner

`services.py` ánh xạ các cổng phổ biến sang tên dịch vụ (ví dụ `22` → `ssh`,
`80` → `http`, `3306` → `mysql`). Với mỗi cổng mở, chương trình kết nối lại và
đọc tối đa 1024 byte đầu tiên với timeout ngắn (`--banner-timeout`). Với các cổng
HTTP phổ biến, chương trình gửi một yêu cầu `HEAD` tối giản để máy chủ trả về
header, thường có `Server:`. Banner sau đó được rút gọn thành một dòng ngắn.

Các cổng TLS như `443` hoặc `8443` thường không trả banner plaintext nên có thể
không có banner; tên dịch vụ vẫn được hiển thị theo bảng ánh xạ.

## An toàn

- Chỉ quét máy của bạn, mạng nhà bạn hoặc máy ảo lab.
- Nếu mục tiêu nằm ngoài các dải nội bộ (`10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, `127.0.0.0/8`), chương trình sẽ cảnh báo và yêu cầu xác
  nhận trước khi quét.
- Không có tính năng né tránh phát hiện (IDS evasion) hay quét tốc độ cao gây
  quá tải.
