"""
RFC 6979 — sinh số ngẫu nhiên k TẤT ĐỊNH cho DSA từ (khóa bí mật x, giá trị băm h).

Vì sao cần (Bài 6, mục 6.4.8): nếu hai chữ ký dùng chung k thì
    k = (H₁ − H₂)(s₁ − s₂)⁻¹ mod q,   x = (s₁·k − H₁)·r⁻¹ mod q   → lộ khóa bí mật.
Sinh k bằng HMAC-DRBG(x, h) bảo đảm: cùng thông điệp → cùng k (vô hại), khác thông điệp → k khác,
và không phụ thuộc chất lượng bộ sinh số ngẫu nhiên của máy.
"""
from .hmac import hmac_sha256


def _bits2int(b: bytes, qlen: int) -> int:
    x = int.from_bytes(b, "big")
    blen = len(b) * 8
    return x >> (blen - qlen) if blen > qlen else x


def rfc6979_k(x: int, h: bytes, q: int):
    """Sinh dãy ứng viên k ∈ [1, q−1] (generator; lấy tiếp nếu k cho r = 0 hoặc s = 0)."""
    qlen = q.bit_length()
    rlen = (qlen + 7) // 8
    x_oct = x.to_bytes(rlen, "big")
    h_oct = (_bits2int(h, qlen) % q).to_bytes(rlen, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac_sha256(k, v + b"\x00" + x_oct + h_oct)
    v = hmac_sha256(k, v)
    k = hmac_sha256(k, v + b"\x01" + x_oct + h_oct)
    v = hmac_sha256(k, v)
    while True:
        t = b""
        while len(t) * 8 < qlen:
            v = hmac_sha256(k, v)
            t += v
        cand = _bits2int(t, qlen)
        if 1 <= cand < q:
            yield cand
        k = hmac_sha256(k, v + b"\x00")
        v = hmac_sha256(k, v)
