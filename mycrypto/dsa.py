"""
DSA — Digital Signature Algorithm (FIPS 186-4; Bài 6, mục 6.4.6).

    Tham số:  q nguyên tố N bit, p nguyên tố L bit với q | p − 1,  g = h^((p−1)/q) mod p  (bậc q)
    Khóa:     x ∈ [1, q−1] bí mật,  y = gˣ mod p công khai
    Ký:       r = (gᵏ mod p) mod q,   s = k⁻¹(H(m) + x·r) mod q
    Xác minh: w = s⁻¹,  u₁ = H·w,  u₂ = r·w,  v = (g^u₁ · y^u₂ mod p) mod q  ≟  r

Chữ ký chỉ gồm 2 số modulo q (2 × 256 bit) dù p dài 2048 bit.
Lưu ý: FIPS 186-5 (2023) không còn cho phép dùng DSA để tạo chữ ký mới — ở đây để học.
"""
import secrets
from dataclasses import dataclass

from .numtheory import mod_pow, mod_inverse, random_prime, is_probable_prime
from .rfc6979 import rfc6979_k
from .sha256 import sha256


@dataclass
class DSAParams:
    p: int
    q: int
    g: int


@dataclass
class DSAPrivateKey:
    p: int
    q: int
    g: int
    x: int
    y: int

    @property
    def params(self):
        return DSAParams(self.p, self.q, self.g)

    def to_dict(self):
        return {k: hex(v) for k, v in self.__dict__.items()}

    @classmethod
    def from_dict(cls, d):
        return cls(**{k: int(v, 16) for k, v in d.items()})


def generate_params(L: int = 2048, N: int = 256, rounds: int = 40) -> DSAParams:
    """
    Sinh (p, q, g) theo ý tưởng FIPS 186-4 A.1.1: chọn q nguyên tố N bit, rồi tìm p = X − (X mod 2q) + 1
    (L bit) cho đến khi p nguyên tố. Khi đó q | p − 1.
    """
    q = random_prime(N, rounds)
    while True:
        X = secrets.randbits(L) | (1 << (L - 1))
        p = X - (X % (2 * q)) + 1
        if p.bit_length() == L and is_probable_prime(p, rounds):
            break
    h = 2
    while True:
        g = mod_pow(h, (p - 1) // q, p)
        if g > 1:
            return DSAParams(p, q, g)
        h += 1


def validate_params(prm: DSAParams) -> bool:
    return (is_probable_prime(prm.p) and is_probable_prime(prm.q) and (prm.p - 1) % prm.q == 0
            and 1 < prm.g < prm.p and mod_pow(prm.g, prm.q, prm.p) == 1)


def generate_keypair(params: DSAParams = None) -> DSAPrivateKey:
    prm = params or generate_params()
    x = 1 + secrets.randbelow(prm.q - 1)
    return DSAPrivateKey(prm.p, prm.q, prm.g, x, mod_pow(prm.g, x, prm.p))


def _hash_int(h: bytes, q: int) -> int:
    """Lấy N bit trái nhất của giá trị băm (FIPS 186-4, 4.6)."""
    z = int.from_bytes(h, "big")
    excess = len(h) * 8 - q.bit_length()
    return z >> excess if excess > 0 else z


def sign_int(p, q, g, x, z: int, k: int):
    """Phép ký trên số nguyên (dùng cho cả ví dụ số nhỏ trên slide)."""
    r = mod_pow(g, k, p) % q
    s = mod_inverse(k, q) * (z + x * r) % q
    return r, s


def verify_int(p, q, g, y, z: int, r: int, s: int) -> bool:
    if not (0 < r < q and 0 < s < q):     # bắt buộc kiểm tra khoảng (bài tập về nhà 4.3)
        return False
    w = mod_inverse(s, q)
    u1, u2 = z * w % q, r * w % q
    v = mod_pow(g, u1, p) * mod_pow(y, u2, p) % p % q
    return v == r


def sign(key: DSAPrivateKey, message: bytes) -> bytes:
    h = sha256(message)
    z = _hash_int(h, key.q)
    nlen = (key.q.bit_length() + 7) // 8
    for k in rfc6979_k(key.x, h, key.q):
        r, s = sign_int(key.p, key.q, key.g, key.x, z, k)
        if r and s:
            return r.to_bytes(nlen, "big") + s.to_bytes(nlen, "big")


def verify(p, q, g, y, message: bytes, signature: bytes) -> bool:
    nlen = (q.bit_length() + 7) // 8
    if len(signature) != 2 * nlen:
        return False
    r = int.from_bytes(signature[:nlen], "big")
    s = int.from_bytes(signature[nlen:], "big")
    return verify_int(p, q, g, y, _hash_int(sha256(message), q), r, s)
