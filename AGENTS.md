# Port Scanner

## Mô tả dự án
Công cụ quét cổng TCP, dùng để học về mạng máy tính (TCP handshake, socket).
Chức năng chính: nhập một IP, tên miền hoặc dải CIDR cùng dải cổng, chương trình
kiểm tra cổng nào đang mở, nhận diện dịch vụ phổ biến (HTTP, SSH, DNS...) và
xuất báo cáo kết quả.

## Công nghệ
- Ngôn ngữ: Python 3.11+
- Thư viện: chỉ dùng thư viện chuẩn (`socket`, `concurrent.futures`, `argparse`,
  `ipaddress`). Hỏi tôi trước khi thêm thư viện bên ngoài.
- Giao diện: [CLI trước, sau đó có thể thêm web UI]

## Cấu trúc thư mục
- `scanner.py`: logic quét cổng
- `main.py`: điểm vào chương trình, xử lý tham số dòng lệnh
- `services.py`: bảng ánh xạ số cổng sang tên dịch vụ
- `report.py`: xuất báo cáo JSON/CSV
- `web_server.py`: web server cục bộ, chỉ bind 127.0.0.1
- `web/`: giao diện web tĩnh (`index.html`)
- `tests/`: kiểm thử tự động bằng `unittest`
- `README.md`: hướng dẫn sử dụng

Chạy kiểm thử: `.venv\Scripts\python.exe -m unittest discover tests`

## Cách chạy
    python main.py 127.0.0.1 --ports 1-1024
    python main.py 192.168.1.0/24 --ports 22,80,443 --timeout 1

## Yêu cầu khi viết code
- Quét song song bằng thread pool để nhanh, có giới hạn số luồng (mặc định 100).
- Mỗi kết nối có timeout, không để treo chương trình.
- Xử lý lỗi rõ ràng: IP sai định dạng, mất mạng, bị chặn.
- Code có chú thích ngắn gọn bằng tiếng Việt giải thích phần liên quan đến mạng
  (ví dụ: vì sao `connect_ex` trả về 0 nghĩa là cổng mở).
- Đặt tên biến, hàm bằng tiếng Anh.

## Giới hạn an toàn (quan trọng)
- Đây là công cụ học tập: chỉ quét máy của tôi, mạng nhà tôi, hoặc máy ảo lab.
- Mặc định khi chạy không có tham số thì chỉ quét `127.0.0.1`.
- Nếu mục tiêu không phải IP nội bộ (ngoài dải 10.x, 172.16-31.x, 192.168.x,
  127.x), in cảnh báo và yêu cầu người dùng xác nhận mới quét.
- Không thêm tính năng né tránh phát hiện (IDS evasion) hay quét tốc độ cao
  gây quá tải.
- Web server chỉ bind `127.0.0.1`. Không bind `0.0.0.0` và không thêm tham số nào
  để đổi địa chỉ bind, vì mở ra mạng LAN sẽ cho người khác dùng máy tôi để quét.

## Lộ trình
1. Quét một IP, một dải cổng bằng TCP connect, có thread pool (mặc định 100 luồng) và timeout
2. Nhận diện dịch vụ và banner grabbing
3. Quét cả dải CIDR
4. Xuất báo cáo JSON/CSV
5. Giao diện web hiển thị kết quả — đã hoàn thành (`web_server.py` + `web/index.html`)
   
Mỗi lần chỉ làm MỘT bước trong lộ trình, xong thì commit và push theo quy tắc Git bên dưới.

# Quy tắc làm việc

## Git
- Sau khi hoàn thành MỘT task (tính năng chạy được, đã tự kiểm tra), hãy:
  1. `git status` để xem những file đã thay đổi
  2. `git add` các file liên quan (không dùng `git add .` mù quáng)
  3. `git commit -m "<type>: <mô tả ngắn>"` với type là feat, fix, docs, refactor
  4. `git push origin agent-web`
- Mỗi task một commit riêng, không gộp nhiều task.
- Không commit file `.env`, khóa bí mật, hoặc thư mục `__pycache__`, `node_modules`.
- Tuyệt đối không dùng `git push --force` hay `git reset --hard`.
- Nếu push bị từ chối, DỪNG LẠI và báo cho tôi, không tự xử lý.

## Kiểm tra trước khi commit
- Chạy thử chương trình, đảm bảo không lỗi cú pháp.
- Nếu task chưa chạy được thì không commit.

## Khi push thất bại
- Nếu `git push` lỗi liên quan SSH/MSYS2: không tự sửa cấu hình, không đổi remote sang HTTPS.
- Giữ nguyên commit ở local, báo tôi mã commit và lệnh push cần chạy.

## Môi trường Python
- Luôn dùng Python trong virtual environment: `.venv\Scripts\python.exe`
- Chạy chương trình bằng: `.venv\Scripts\python.exe main.py`
- Cài thư viện bằng: `.venv\Scripts\python.exe -m pip install <tên>`
- Không dùng lệnh `python` hay `pip` trần (trên máy này chúng trỏ vào bản MSYS2).