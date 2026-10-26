"""
Hạ tầng khóa công khai thu nhỏ (Bài 6, mục 6.4.10).

Vấn đề: khóa công khai đính kèm trong file có thật là của người ký không? (chống thay khóa / MITM)
Giải pháp: một CA (Certificate Authority) mà bên xác minh tin cậy ký lên cặp (danh tính, khóa công khai).

    Chứng chỉ = { v, serial, subject, issuer, alg, pub (SPKI), not_before, not_after, ca_fp }  +  sig_CA
    Xác minh chuỗi:  khóa CA tin cậy → chữ ký CA trên chứng chỉ → khóa trong chứng chỉ = khóa ký file
    Thu hồi:         danh sách CRL (serial bị thu hồi) khi khóa bị lộ

Đây là mô hình đơn giản hóa của X.509 (một cấp, không có CA trung gian, định dạng JSON thay vì ASN.1).
CA ký chứng chỉ bằng RSA-PSS 2048 tự cài đặt (cùng thuật toán với mycrypto/rsa.py).
"""
import base64
import json
import secrets
from datetime import datetime, timedelta, timezone

import config
from mycrypto import rsa, der
from .keys import fingerprint, format_fingerprint


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _tbs_bytes(cert: dict) -> bytes:
    """Phần được CA ký: mọi trường trừ 'sig', JSON chuẩn hóa (khóa sắp xếp, không khoảng trắng)."""
    tbs = {k: v for k, v in cert.items() if k != "sig"}
    return json.dumps(tbs, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------- CA
def _ca_path():
    return config.KEYS_DIR / "ca.json"


def load_ca():
    """
    Trả về (khóa RSA của CA, tên CA); tạo mới nếu chưa có.
    File ca.json kiểu cũ (CA Ed25519 của phiên bản trước) được đổi tên thành ca-old.json và tạo CA mới.
    """
    path = _ca_path()
    if path.exists():
        d = json.loads(path.read_text())
        if d.get("alg") == "RSA-PSS":
            return rsa.RSAPrivateKey.from_dict(d["private"]), d["name"]
        path.rename(path.with_name("ca-old.json"))
    key = rsa.generate_keypair(config.RSA_BITS, config.RSA_E, config.MILLER_RABIN_ROUNDS)
    config.KEYS_DIR.mkdir(exist_ok=True)
    path.write_text(json.dumps({"alg": "RSA-PSS", "name": config.CA_NAME, "created": _iso(_now()),
                                "private": key.to_dict()}, indent=2))
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key, config.CA_NAME


def ca_spki() -> bytes:
    key, _ = load_ca()
    return der.spki_rsa(key.n, key.e)


def ca_info() -> dict:
    _, name = load_ca()
    spki = ca_spki()
    return {"name": name, "alg": "RSA-PSS", "fingerprint": format_fingerprint(fingerprint(spki)),
            "pem": der.to_pem(spki), "revoked": sorted(load_crl())}


# ---------------------------------------------------------------- cấp / kiểm tra chứng chỉ
def issue(subject: str, spki: bytes, alg_label: str, days: int = None) -> dict:
    key, name = load_ca()
    now = _now()
    cert = {
        "v": 1,
        "serial": secrets.token_hex(8),
        "subject": subject or "(khong ten)",
        "issuer": name,
        "alg": alg_label,
        "pub": base64.b64encode(spki).decode(),
        "not_before": _iso(now),
        "not_after": _iso(now + timedelta(days=days or config.CERT_VALID_DAYS)),
        "ca_fp": fingerprint(der.spki_rsa(key.n, key.e)),
    }
    cert["sig"] = base64.b64encode(rsa.sign(key, _tbs_bytes(cert), config.RSA_PSS_SALT_LEN)).decode()
    return cert


def verify_certificate(cert: dict, signed_pub_b64: str, at_time: str = None):
    """
    Kiểm tra chứng chỉ, trả về danh sách (ok, thông báo).
    ok = True/False, hoặc None nếu chỉ là cảnh báo.
    """
    out = []
    ca_key, ca_name = load_ca()
    trusted_fp = fingerprint(der.spki_rsa(ca_key.n, ca_key.e))
    if cert.get("ca_fp") != trusted_fp:
        out.append((False, f"Chứng chỉ do CA khác cấp (không nằm trong danh sách CA tin cậy: {ca_name})"))
        return out
    try:
        sig_ok = rsa.verify(ca_key.public_key(), _tbs_bytes(cert), base64.b64decode(cert["sig"]),
                            config.RSA_PSS_SALT_LEN)
    except Exception:
        sig_ok = False
    out.append((sig_ok, f"Chữ ký của CA \"{ca_name}\" trên chứng chỉ hợp lệ" if sig_ok
                else "Chữ ký CA trên chứng chỉ KHÔNG hợp lệ: chứng chỉ bị làm giả hoặc sửa đổi"))

    same = cert.get("pub") == signed_pub_b64
    out.append((same, f"Khóa ký file trùng khóa trong chứng chỉ của \"{cert.get('subject')}\"" if same
                else "Khóa ký file KHÁC khóa trong chứng chỉ: có thể bị thay khóa"))

    t = _parse(at_time) if at_time else _now()
    in_range = _parse(cert["not_before"]) <= t <= _parse(cert["not_after"])
    out.append((in_range, f"Chứng chỉ còn hiệu lực tại thời điểm ký ({cert['not_before'][:10]} → {cert['not_after'][:10]})"
                if in_range else "Chứng chỉ đã hết hạn hoặc chưa có hiệu lực tại thời điểm ký"))

    revoked = cert.get("serial") in load_crl()
    out.append((not revoked, "Chứng chỉ chưa bị thu hồi (CRL)" if not revoked
                else f"Chứng chỉ serial {cert.get('serial')} ĐÃ BỊ THU HỒI"))
    return out


# ---------------------------------------------------------------- CRL
def _crl_path():
    return config.KEYS_DIR / "crl.json"


def load_crl() -> set:
    p = _crl_path()
    return set(json.loads(p.read_text())) if p.exists() else set()


def revoke(serial: str) -> None:
    crl = load_crl() | {serial}
    config.KEYS_DIR.mkdir(exist_ok=True)
    _crl_path().write_text(json.dumps(sorted(crl)))
