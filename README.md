# BTL Mã hóa thông tin nâng cao
# Ký số (Python): demo web chữ ký số RSA, ElGamal, DSA

Web demo **tải file lên → ký số → nhúng chữ ký vào file → xác minh**, kèm CA demo cấp chứng chỉ.
Thuật toán mật mã được **tự cài đặt** trong `mycrypto/`, không dùng thư viện mã hóa. Flask chỉ làm web server.

Môn học: COSC63170 · Mã hóa thông tin nâng cao (Bài 6, phần 4: Chữ ký số và PKI).

## Lược đồ chữ ký

| Lược đồ | Bài toán khó | Chữ ký | Khóa công khai (SPKI) | Ghi chú |
|---|---|---|---|---|
| RSA-PSS 2048 | Phân tích thừa số | 256 byte | 294 byte | Đệm PSS ngẫu nhiên, ký nhanh bằng CRT |
| ElGamal 2048 | Logarit rời rạc | 512 byte | ~550 byte | Nhóm RFC 3526; k ngẫu nhiên mới mỗi lần |
| DSA (2048, 256) | Logarit rời rạc | 64 byte | ~840 byte | k tất định theo RFC 6979 |

CA demo ký chứng chỉ bằng RSA-PSS 2048.

## Cấu trúc project

```
ky-so-python/
├── config.py            # ⚙ CẤU HÌNH
├── app.py               # Flask: /, /api/keys, /api/sign, /api/verify, /api/ca, /api/revoke
├── wsgi.py              # điểm vào cho Gunicorn
├── mycrypto/            # ★ MẬT MÃ TỰ CÀI ĐẶT
│   ├── sha256.py        #   SHA-256 (FIPS 180-4)
│   ├── hmac.py          #   HMAC-SHA256 (RFC 2104), dùng trong rfc6979
│   ├── numtheory.py     #   mod_pow, Euclid mở rộng, Miller-Rabin, sinh số nguyên tố, căn nguyên thủy
│   ├── rsa.py           #   RSA-PSS + MGF1 + CRT (RFC 8017)
│   ├── elgamal.py       #   chữ ký ElGamal trên nhóm RFC 3526
│   ├── dsa.py           #   DSA: sinh tham số, ký, xác minh (FIPS 186-4)
│   ├── rfc6979.py       #   sinh k tất định cho DSA
│   └── der.py           #   SPKI (DER) / PEM cho RSA, DSA, ElGamal
├── signing/
│   ├── keys.py          #   3 lược đồ, kho khóa, tham số DSA dùng chung
│   ├── pki.py           #   CA demo, cấp/kiểm tra chứng chỉ, CRL
│   ├── format.py        #   thông điệp chuẩn hóa M, khối %DSIG
│   ├── signer.py        #   băm → ký → nhúng
│   └── verifier.py      #   7 bước xác minh
├── templates/           # base.html, index.html
├── static/              # style.css, app.js
├── keys/                # khóa sinh ra khi chạy (khóa người ký, CA, tham số DSA, CRL)
├── deploy/              # chạy dịch vụ systemd trên Ubuntu
└── docs/THIET-KE.md
```

## Chạy trên máy cá nhân

```bash
cd btl-ma-hoa
# Cách 1: chạy trên môi trường ảo
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt                        # chỉ Flask
python app.py                                          # http://127.0.0.1:5000
# Cách 2: chạy trực tiếp
pip3 install -r requirements.txt                        # chỉ Flask
python3 app.py                                          # http://127.0.0.1:5000
```

Yêu cầu Python 3.9 trở lên.

## Chạy thành dịch vụ trên Ubuntu (systemd + Gunicorn)

```bash
# 1. Sửa khối CẤU HÌNH ở đầu deploy/install.sh (cổng, user, thư mục, Apache…)
# 2. Cài (chạy lại mỗi khi cập nhật code; keys/ được giữ nguyên)
sudo bash deploy/install.sh

systemctl status ky-so          # trạng thái
journalctl -u ky-so -f          # nhật ký
sudo bash deploy/uninstall.sh   # gỡ (mặc định giữ /opt/ky-so/keys)
```

| File | Vai trò |
|---|---|
| `deploy/install.sh` | Cài gói, tạo user `kyso`, chép code vào `/opt/ky-so`, tạo venv, khởi tạo CA, bật dịch vụ |
| `deploy/ky-so.service` | Mẫu unit systemd (chỉ ghi được `keys/`) |
| `deploy/apache-ky-so.conf` | VirtualHost :80 reverse proxy (`USE_APACHE="yes"`) |
| `deploy/apache-ky-so-ssl.conf` | VirtualHost :443 khi đặt `SSL_CERT`, `SSL_KEY` |
| `deploy/uninstall.sh` | Gỡ dịch vụ và vhost Apache |

## Cấu hình (`config.py`)

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `HOST`, `PORT` | `127.0.0.1`, `5000` | Địa chỉ khi chạy `python app.py` |
| `MAX_UPLOAD_MB` | `5` | Giới hạn file (SHA-256 thuần Python ≈ 0,4 MB/s) |
| `DEFAULT_ALGORITHM` | `RSA-PSS` | `RSA-PSS`, `ElGamal` hoặc `DSA` |
| `RSA_BITS`, `RSA_E` | `2048`, `65537` | Tham số RSA |
| `DSA_L`, `DSA_N` | `2048`, `256` | Tham số DSA, sinh một lần và lưu `keys/dsa-params.json` |
| `CA_NAME`, `CERT_VALID_DAYS` | `COM608 Demo Root CA`, `365` | CA demo |

## Nâng cấp từ phiên bản trước

Phiên bản trước có CA Ed25519 và các khóa ECDSA/Ed25519/Schnorr. Khi chạy bản này:
- `keys/ca.json` cũ được đổi tên thành `keys/ca-old.json` và CA RSA-PSS mới được tạo;
- khóa của thuật toán đã bỏ bị ẩn khỏi danh sách;
- chứng chỉ cũ không còn hợp lệ với CA mới → **tạo khóa mới** để ký.

## Giới hạn

- Mã phục vụ học tập: không chạy trong thời gian hằng, có thể bị tấn công kênh kề.
- Khóa bí mật và khóa CA lưu dạng JSON không mã hóa trong `keys/`.
- Chứng chỉ là mô hình rút gọn của X.509 (JSON, một cấp CA, CRL cục bộ).
- Chữ ký không có giá trị pháp lý và không theo chuẩn PAdES.
