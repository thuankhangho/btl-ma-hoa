"""
Quản lý cặp khóa cho 3 lược đồ chữ ký: RSA-PSS, ElGamal, DSA.

Mỗi khóa: sinh, lưu/đọc kho khóa, xuất SPKI/PEM, dấu vân tay, ký; xác minh bằng SPKI.
"""
import json
import time
from dataclasses import dataclass, field

import config
from mycrypto import rsa, der, dsa, elgamal
from mycrypto.sha256 import sha256

# Thông tin hiển thị cho từng lược đồ (Bài 6, bảng 6.4.11)
ALGORITHMS = {
    "RSA-PSS": {"name": f"RSA-PSS {config.RSA_BITS}", "problem": "Phân tích thừa số", "note": "đệm ngẫu nhiên PSS, xác minh nhanh"},
    "ElGamal": {"name": "ElGamal 2048",              "problem": "Logarit rời rạc (DLP)", "note": "chữ ký dài gấp đôi p, k phải mới mỗi lần"},
    "DSA":     {"name": "DSA (2048, 256)",           "problem": "Logarit rời rạc (DLP)", "note": "chữ ký 64 byte, k tất định theo RFC 6979"},
}


# ---------------------------------------------------------------- tham số miền DSA dùng chung
def domain_params() -> dsa.DSAParams:
    """Tham số (p, q, g) công khai, dùng chung cho mọi khóa DSA; sinh một lần rồi lưu lại."""
    path = config.KEYS_DIR / "dsa-params.json"
    if path.exists():
        d = json.loads(path.read_text())
        return dsa.DSAParams(int(d["p"], 16), int(d["q"], 16), int(d["g"], 16))
    prm = dsa.generate_params(config.DSA_L, config.DSA_N, config.MILLER_RABIN_ROUNDS)
    config.KEYS_DIR.mkdir(exist_ok=True)
    path.write_text(json.dumps({"p": hex(prm.p), "q": hex(prm.q), "g": hex(prm.g)}, indent=2))
    return prm


# ---------------------------------------------------------------- khóa ký
@dataclass
class SigningKey:
    alg: str
    private: object
    created: str = ""
    owner: str = ""
    cert: dict = field(default=None)

    @property
    def label(self) -> str:
        k = self.private
        if self.alg == "RSA-PSS":
            return f"RSA-PSS-{k.n.bit_length()}/SHA-256"
        if self.alg == "DSA":
            return f"DSA-{k.p.bit_length()}-{k.q.bit_length()}/SHA-256"
        return f"ElGamal-{k.p.bit_length()}/SHA-256"

    @property
    def spki(self) -> bytes:
        k = self.private
        if self.alg == "RSA-PSS":
            return der.spki_rsa(k.n, k.e)
        if self.alg == "DSA":
            return der.spki_dsa(k.p, k.q, k.g, k.y)
        return der.spki_elgamal(k.p, k.alpha, k.beta)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.spki)

    @property
    def key_id(self) -> str:
        return self.fingerprint[:16]

    def sign(self, message: bytes) -> bytes:
        if self.alg == "RSA-PSS":
            return rsa.sign(self.private, message, config.RSA_PSS_SALT_LEN)
        if self.alg == "DSA":
            return dsa.sign(self.private, message)
        return elgamal.sign(self.private, message)

    def public_info(self) -> dict:
        return {
            "key_id": self.key_id, "alg": self.alg, "label": self.label, "created": self.created,
            "owner": self.owner, "fingerprint": format_fingerprint(self.fingerprint),
            "pem": der.to_pem(self.spki), "spki_bytes": len(self.spki),
            "cert": self.cert, **ALGORITHMS[self.alg],
        }


def fingerprint(spki: bytes) -> str:
    """Dấu vân tay = SHA-256(SPKI DER), dạng hex."""
    return sha256(spki).hex()


def format_fingerprint(h: str) -> str:
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2)).upper()


def normalize_fingerprint(s: str) -> str:
    return "".join(c for c in (s or "").lower() if c in "0123456789abcdef")


def generate(alg: str, owner: str = "") -> SigningKey:
    if alg == "RSA-PSS":
        priv = rsa.generate_keypair(config.RSA_BITS, config.RSA_E, config.MILLER_RABIN_ROUNDS)
    elif alg == "DSA":
        priv = dsa.generate_keypair(domain_params())
    elif alg == "ElGamal":
        priv = elgamal.generate_keypair()
    else:
        raise ValueError("Thuật toán không hỗ trợ: " + alg)
    return SigningKey(alg, priv, time.strftime("%Y-%m-%dT%H:%M:%S"), owner)


def verify_with_spki(spki: bytes, message: bytes, signature: bytes) -> bool:
    """Khôi phục khóa công khai từ SPKI rồi xác minh bằng lược đồ tương ứng."""
    kind, a, b = der.parse_spki(spki)
    if kind == "RSA":
        return rsa.verify(rsa.RSAPublicKey(a, b), message, signature, config.RSA_PSS_SALT_LEN)
    if kind == "DSA":
        return dsa.verify(*a, b, message, signature)
    return elgamal.verify(*a, b, message, signature)


# ---------------------------------------------------------------- kho khóa (file JSON)
_PRIVATE_CLASSES = {"RSA-PSS": rsa.RSAPrivateKey, "DSA": dsa.DSAPrivateKey, "ElGamal": elgamal.ElGamalPrivateKey}


def save(key: SigningKey) -> None:
    config.KEYS_DIR.mkdir(exist_ok=True)
    data = {"alg": key.alg, "created": key.created, "owner": key.owner,
            "private": key.private.to_dict(), "cert": key.cert}
    path = config.KEYS_DIR / f"{key.key_id}.json"
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    try:
        path.chmod(0o600)   # chỉ chủ sở hữu được đọc
    except OSError:
        pass


def load(key_id: str) -> SigningKey:
    if not key_id.isalnum():
        raise ValueError("key_id không hợp lệ")
    data = json.loads((config.KEYS_DIR / f"{key_id}.json").read_text())
    if data["alg"] not in _PRIVATE_CLASSES:
        raise ValueError("Thuật toán không còn được hỗ trợ: " + data["alg"])
    priv = _PRIVATE_CLASSES[data["alg"]].from_dict(data["private"])
    return SigningKey(data["alg"], priv, data.get("created", ""), data.get("owner", ""), data.get("cert"))


def list_keys() -> list:
    """Danh sách khóa dùng được; bỏ qua file khóa của thuật toán đã gỡ khỏi demo."""
    if not config.KEYS_DIR.exists():
        return []
    out = []
    for p in config.KEYS_DIR.glob("*.json"):
        if not (p.stem.isalnum() and len(p.stem) == 16):
            continue
        try:
            out.append(load(p.stem))
        except (ValueError, KeyError):
            continue
    return sorted(out, key=lambda k: k.created, reverse=True)
