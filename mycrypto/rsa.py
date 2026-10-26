"""
RSA và lược đồ chữ ký RSASSA-PSS (RFC 8017, mục 8.1 và 9.1), băm SHA-256, MGF1-SHA256.

    Sinh khóa:  n = p·q,  λ(n) = lcm(p−1, q−1),  d = e⁻¹ mod λ(n)
    Ký:         EM = EMSA-PSS-ENCODE(M),  s = EM^d mod n   (tính nhanh bằng CRT)
    Xác minh:   EM = s^e mod n,  EMSA-PSS-VERIFY(M, EM)
"""
import secrets
from dataclasses import dataclass

from .sha256 import sha256, DIGEST_SIZE as H_LEN
from .numtheory import mod_pow, mod_inverse, gcd, random_prime, bytes_to_int, int_to_bytes


@dataclass
class RSAPublicKey:
    n: int
    e: int

    @property
    def bits(self):
        return self.n.bit_length()

    @property
    def size(self):          # k: độ dài modulus tính theo byte
        return (self.bits + 7) // 8


@dataclass
class RSAPrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int    # d mod (p−1)
    dq: int    # d mod (q−1)
    qinv: int  # q⁻¹ mod p

    def public_key(self):
        return RSAPublicKey(self.n, self.e)

    def to_dict(self):
        return {k: hex(v) for k, v in self.__dict__.items()}

    @classmethod
    def from_dict(cls, d):
        return cls(**{k: int(v, 16) for k, v in d.items()})


# ---------------------------------------------------------------- sinh khóa
def generate_keypair(bits: int = 2048, e: int = 65537, rounds: int = 40) -> RSAPrivateKey:
    while True:
        p = random_prime(bits // 2, rounds, coprime_to=e)
        q = random_prime(bits - bits // 2, rounds, coprime_to=e)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)   # hàm Carmichael λ(n)
        d = mod_inverse(e, lam)
        if p < q:
            p, q = q, p
        return RSAPrivateKey(n, e, d, p, q, d % (p - 1), d % (q - 1), mod_inverse(q, p))


# ---------------------------------------------------------------- nguyên thủy RSA
def rsasp1(key: RSAPrivateKey, m: int) -> int:
    """s = m^d mod n, dùng Định lý số dư Trung Hoa (CRT), nhanh khoảng 4 lần."""
    s1 = mod_pow(m, key.dp, key.p)
    s2 = mod_pow(m, key.dq, key.q)
    h = (key.qinv * (s1 - s2)) % key.p
    return s2 + key.q * h


def rsavp1(key: RSAPublicKey, s: int) -> int:
    """m = s^e mod n"""
    if not 0 <= s < key.n:
        raise ValueError("Chữ ký ngoài khoảng [0, n)")
    return mod_pow(s, key.e, key.n)


# ---------------------------------------------------------------- MGF1 và PSS
def mgf1(seed: bytes, length: int) -> bytes:
    """Hàm sinh mặt nạ: T = H(seed ‖ 0) ‖ H(seed ‖ 1) ‖ …, cắt lấy `length` byte."""
    out = b""
    counter = 0
    while len(out) < length:
        out += sha256(seed + counter.to_bytes(4, "big"))
        counter += 1
    return out[:length]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def emsa_pss_encode(m_hash: bytes, em_bits: int, salt: bytes) -> bytes:
    em_len = (em_bits + 7) // 8
    s_len = len(salt)
    if em_len < H_LEN + s_len + 2:
        raise ValueError("Khóa quá ngắn")
    m_prime = b"\x00" * 8 + m_hash + salt          # M' = 0x00×8 ‖ mHash ‖ salt
    h = sha256(m_prime)                            # H = Hash(M')
    ps = b"\x00" * (em_len - s_len - H_LEN - 2)
    db = ps + b"\x01" + salt                       # DB = PS ‖ 0x01 ‖ salt
    masked_db = bytearray(_xor(db, mgf1(h, em_len - H_LEN - 1)))
    masked_db[0] &= 0xFF >> (8 * em_len - em_bits)  # xóa các bit thừa bên trái
    return bytes(masked_db) + h + b"\xbc"           # EM = maskedDB ‖ H ‖ 0xbc


def emsa_pss_verify(m_hash: bytes, em: bytes, em_bits: int, s_len: int) -> bool:
    em_len = (em_bits + 7) // 8
    if em_len < H_LEN + s_len + 2 or len(em) != em_len or em[-1] != 0xBC:
        return False
    masked_db, h = em[:em_len - H_LEN - 1], em[em_len - H_LEN - 1:-1]
    top_bits = 8 * em_len - em_bits
    if top_bits and (masked_db[0] >> (8 - top_bits)) != 0:
        return False   # các bit thừa bên trái phải bằng 0
    db = bytearray(_xor(masked_db, mgf1(h, em_len - H_LEN - 1)))
    db[0] &= 0xFF >> top_bits
    ps_len = em_len - H_LEN - s_len - 2
    if any(db[:ps_len]) or db[ps_len] != 0x01:
        return False
    salt = bytes(db[-s_len:]) if s_len else b""
    return sha256(b"\x00" * 8 + m_hash + salt) == h


# ---------------------------------------------------------------- ký / xác minh
def sign(key: RSAPrivateKey, message: bytes, salt_len: int = 32) -> bytes:
    mod_bits = key.n.bit_length()
    k = (mod_bits + 7) // 8
    em = emsa_pss_encode(sha256(message), mod_bits - 1, secrets.token_bytes(salt_len))
    s = rsasp1(key, bytes_to_int(em))
    return int_to_bytes(s, k)


def verify(key: RSAPublicKey, message: bytes, signature: bytes, salt_len: int = 32) -> bool:
    if len(signature) != key.size:
        return False
    try:
        m = rsavp1(key, bytes_to_int(signature))
    except ValueError:
        return False
    em_bits = key.bits - 1
    em_len = (em_bits + 7) // 8
    if m >= 256 ** em_len:
        return False
    return emsa_pss_verify(sha256(message), int_to_bytes(m, em_len), em_bits, salt_len)
