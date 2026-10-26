"""SHA-256 theo FIPS 180-4, viết tay bằng Python thuần."""

# 64 hằng số K: 32 bit đầu phần thập phân căn bậc ba của 64 số nguyên tố đầu tiên
_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Giá trị băm khởi tạo H0: 32 bit đầu phần thập phân căn bậc hai của 8 số nguyên tố đầu tiên
_H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

_M32 = 0xFFFFFFFF
BLOCK_SIZE = 64    # byte
DIGEST_SIZE = 32   # byte


def _rotr(x, n):
    """Xoay phải 32 bit."""
    return ((x >> n) | (x << (32 - n))) & _M32


def _compress(state, block, K=_K, M=_M32):
    """
    Hàm nén: xử lý một khối 512 bit, cập nhật trạng thái 8 từ 32 bit.
    Các phép xoay ROTR được viết trực tiếp (không gọi hàm) để chạy nhanh hơn trong Python.

        σ0(x) = ROTR7 ⊕ ROTR18 ⊕ SHR3      σ1(x) = ROTR17 ⊕ ROTR19 ⊕ SHR10
        Σ0(a) = ROTR2 ⊕ ROTR13 ⊕ ROTR22    Σ1(e) = ROTR6 ⊕ ROTR11 ⊕ ROTR25
        Ch(e,f,g) = (e ∧ f) ⊕ (¬e ∧ g)      Maj(a,b,c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)
    """
    w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    # Phép dịch trái có thể để lại bit trên bit 31; mọi tổng đều được & M nên kết quả vẫn đúng mod 2^32.
    for t in range(16, 64):
        x, y = w[t - 15], w[t - 2]
        s0 = ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3)
        s1 = ((y >> 17) | (y << 15)) ^ ((y >> 19) | (y << 13)) ^ (y >> 10)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & M)

    a, b, c, d, e, f, g, h = state
    for t in range(64):
        S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
        t1 = (h + (S1 & M) + ((e & f) ^ (~e & g)) + K[t] + w[t]) & M
        S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
        t2 = ((S0 & M) + ((a & b) ^ (a & c) ^ (b & c))) & M
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & M, c, b, a, (t1 + t2) & M

    return [(x + y) & M for x, y in zip(state, (a, b, c, d, e, f, g, h))]


class SHA256:
    """Giao diện kiểu hashlib: update() nhiều lần, digest() ở cuối."""

    def __init__(self, data=b""):
        self._state = list(_H0)
        self._buf = b""
        self._len = 0
        if data:
            self.update(data)

    def update(self, data):
        data = bytes(data)
        self._len += len(data)
        buf = self._buf + data
        full = len(buf) - len(buf) % 64
        for i in range(0, full, 64):
            self._state = _compress(self._state, buf[i:i + 64])
        self._buf = buf[full:]
        return self

    def digest(self):
        # Đệm: 1 bit '1', các bit '0', rồi độ dài thông điệp (bit) 64 bit big-endian
        bit_len = self._len * 8
        pad = b"\x80" + b"\x00" * ((55 - self._len) % 64) + bit_len.to_bytes(8, "big")
        state = list(self._state)
        tail = self._buf + pad
        for i in range(0, len(tail), 64):
            state = _compress(state, tail[i:i + 64])
        return b"".join(x.to_bytes(4, "big") for x in state)

    def hexdigest(self):
        return self.digest().hex()


def sha256(data: bytes) -> bytes:
    return SHA256(data).digest()
