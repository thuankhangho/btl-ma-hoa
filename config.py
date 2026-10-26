# =====================================================================
#  CẤU HÌNH — chỉnh tại đây
# =====================================================================
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# ---- Web server ----
HOST = "0.0.0.0"              # 0.0.0.0: máy khác trong mạng truy cập được; 127.0.0.1: chỉ máy này
PORT = 5000
DEBUG = False
MAX_UPLOAD_MB = 5             # SHA-256 viết tay bằng Python thuần chỉ đạt ~0,4 MB/s (≈ 2,5 s cho 1 MB)

# ---- Kho khóa (demo: lưu file JSON, KHÔNG mã hóa khóa bí mật) ----
KEYS_DIR = BASE_DIR / "keys"

# ---- Thuật toán ----
DEFAULT_ALGORITHM = "RSA-PSS" # "RSA-PSS" | "ElGamal" | "DSA"
RSA_BITS = 2048               # độ dài modulus n
RSA_E = 65537                 # số mũ công khai
RSA_PSS_SALT_LEN = 32         # byte, bằng độ dài đầu ra SHA-256
MILLER_RABIN_ROUNDS = 40      # xác suất sai ≤ 4^-40
DSA_L, DSA_N = 2048, 256      # độ dài p và q của DSA (FIPS 186-4); sinh một lần, lưu keys/dsa-params.json
# ElGamal dùng nhóm MODP 2048 bit của RFC 3526 (hằng số trong mycrypto/elgamal.py)

# ---- PKI demo (Bài 6, mục 6.4.10): CA ký chứng chỉ bằng RSA-PSS ----
CA_NAME = "COM608 Demo Root CA"
CERT_VALID_DAYS = 365

# ---- Định dạng khối chữ ký nhúng (tương thích bản JavaScript) ----
FORMAT_VERSION = "DSIG-v1"
MARKER_BEGIN = b"\n%DSIG-BEGIN "
MARKER_END = b" %DSIG-END"
TRAILER_END = b"\n"
TRAILER_SEARCH_WINDOW = 1 << 20   # chỉ tìm khối chữ ký trong 1 MiB cuối file

# ---- Giá trị mặc định trên form ----
DEFAULT_SIGNER = "Nguyen Van A"
DEFAULT_REASON = "Phê duyệt tài liệu"

# Định dạng ZIP: nối dữ liệu vào cuối có thể làm phần mềm báo lỗi → nên dùng chữ ký rời
ZIP_BASED_EXTENSIONS = {"docx", "xlsx", "pptx", "zip", "epub", "odt", "jar"}
