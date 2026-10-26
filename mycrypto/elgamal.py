"""
Chữ ký ElGamal (1985; Bài 6, mục 6.4.4), băm SHA-256.

Khóa:      p nguyên tố, α căn nguyên thủy mod p, bí mật a ∈ [1, p−2], công khai β = αᵃ mod p
Ký:        m = SHA-256(M);  k ngẫu nhiên, gcd(k, p−1) = 1
           r = αᵏ mod p,   s = k⁻¹(m − a·r) mod (p−1)              → chữ ký (r, s)
Xác minh:  0 < r < p  và  βʳ · rˢ ≡ αᵐ (mod p)
Đúng vì:   s·k ≡ m − a·r  ⇒  m ≡ a·r + k·s (mod p−1)  ⇒  αᵐ ≡ (αᵃ)ʳ(αᵏ)ˢ = βʳ rˢ (mod p)

p là số nguyên tố an toàn 2048 bit của RFC 3526 (nhóm MODP 14): p = 2q + 1 với q nguyên tố,
nên p − 1 có ước nguyên tố lớn q (chống Pohlig–Hellman).
"""
import secrets
from dataclasses import dataclass
from functools import lru_cache

from .numtheory import mod_pow, mod_inverse, gcd, find_primitive_root
from .sha256 import sha256

# RFC 3526, mục 3 — 2048-bit MODP Group
RFC3526_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
RFC3526_Q = (RFC3526_P - 1) // 2


@lru_cache(maxsize=1)
def default_group():
    """(p, α): α = căn nguyên thủy nhỏ nhất. p − 1 = 2q nên chỉ cần thử hai ước nguyên tố 2 và q."""
    return RFC3526_P, find_primitive_root(RFC3526_P, [2, RFC3526_Q])


@dataclass
class ElGamalPrivateKey:
    p: int
    alpha: int
    a: int
    beta: int

    def to_dict(self):
        return {k: hex(v) for k, v in self.__dict__.items()}

    @classmethod
    def from_dict(cls, d):
        return cls(**{k: int(v, 16) for k, v in d.items()})


def generate_keypair() -> ElGamalPrivateKey:
    p, alpha = default_group()
    a = 1 + secrets.randbelow(p - 2)
    return ElGamalPrivateKey(p, alpha, a, mod_pow(alpha, a, p))


def random_k(p: int) -> int:
    """k ngẫu nhiên, MỚI mỗi lần ký, nguyên tố cùng nhau với p − 1. Tái dùng k làm lộ khóa bí mật a."""
    while True:
        k = 2 + secrets.randbelow(p - 3)
        if gcd(k, p - 1) == 1:
            return k


def sign_int(p, alpha, a, m: int, k: int):
    r = mod_pow(alpha, k, p)
    s = mod_inverse(k, p - 1) * (m - a * r) % (p - 1)
    return r, s


def verify_int(p, alpha, beta, m: int, r: int, s: int) -> bool:
    if not (0 < r < p and 0 <= s < p - 1):
        return False
    return mod_pow(beta, r, p) * mod_pow(r, s, p) % p == mod_pow(alpha, m, p)


def _hash_int(message: bytes) -> int:
    return int.from_bytes(sha256(message), "big")


def sign(key: ElGamalPrivateKey, message: bytes) -> bytes:
    plen = (key.p.bit_length() + 7) // 8
    r, s = sign_int(key.p, key.alpha, key.a, _hash_int(message), random_k(key.p))
    return r.to_bytes(plen, "big") + s.to_bytes(plen, "big")


def verify(p, alpha, beta, message: bytes, signature: bytes) -> bool:
    plen = (p.bit_length() + 7) // 8
    if len(signature) != 2 * plen:
        return False
    r = int.from_bytes(signature[:plen], "big")
    s = int.from_bytes(signature[plen:], "big")
    return verify_int(p, alpha, beta, _hash_int(message), r, s)
