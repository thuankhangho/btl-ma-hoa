"""Số học mô-đun: lũy thừa nhanh, Euclid mở rộng, nghịch đảo, kiểm tra nguyên tố Miller-Rabin."""
import secrets  # nguồn ngẫu nhiên an toàn của hệ điều hành (os.urandom), không phải thư viện mã hóa


def mod_pow(base: int, exp: int, mod: int) -> int:
    """Bình phương và nhân (square-and-multiply), duyệt bit từ trái sang phải. Tính base^exp mod mod."""
    if mod == 1:
        return 0
    result = 1
    base %= mod
    for bit in bin(exp)[2:]:
        result = (result * result) % mod
        if bit == "1":
            result = (result * base) % mod
    return result


def egcd(a: int, b: int):
    """Euclid mở rộng (dạng lặp): trả về (g, x, y) với a·x + b·y = g = gcd(a, b)."""
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def gcd(a: int, b: int) -> int:
    return egcd(a, b)[0]


def mod_inverse(a: int, m: int) -> int:
    """a⁻¹ mod m, tồn tại khi gcd(a, m) = 1."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("Không tồn tại nghịch đảo mô-đun")
    return x % m


def _small_primes(limit=2000):
    """Sàng Eratosthenes, dùng để loại nhanh các ứng viên chia hết cho số nguyên tố nhỏ."""
    sieve = bytearray([1]) * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return [i for i in range(limit + 1) if sieve[i]]


SMALL_PRIMES = _small_primes()


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """
    Miller-Rabin. Viết n − 1 = 2^s · d với d lẻ.
    Với cơ sở a ngẫu nhiên: n "có thể nguyên tố" nếu a^d ≡ 1 hoặc a^(2^r·d) ≡ −1 (mod n) với r nào đó.
    Hợp số qua được một vòng với xác suất ≤ 1/4.
    """
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = mod_pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False   # a là "nhân chứng": n chắc chắn là hợp số
    return True


def random_prime(bits: int, rounds: int = 40, coprime_to: int = None) -> int:
    """Sinh số nguyên tố đúng `bits` bit (2 bit cao nhất = 1 để n = p·q đủ 2·bits bit)."""
    while True:
        cand = secrets.randbits(bits) | (0b11 << (bits - 2)) | 1
        if coprime_to and gcd(cand - 1, coprime_to) != 1:
            continue
        if is_probable_prime(cand, rounds):
            return cand


def bytes_to_int(b: bytes) -> int:      # OS2IP
    return int.from_bytes(b, "big")


def int_to_bytes(x: int, length: int) -> bytes:   # I2OSP
    if x >= 256 ** length:
        raise ValueError("Số nguyên quá lớn")
    return x.to_bytes(length, "big")


# =====================================================================
#  Căn nguyên thủy (dùng cho tham số ElGamal)
# =====================================================================
def is_primitive_root(g: int, p: int, prime_factors) -> bool:
    """g là căn nguyên thủy mod p ⇔ g^((p−1)/q) ≢ 1 với mọi ước nguyên tố q của p − 1."""
    return g % p != 0 and all(mod_pow(g, (p - 1) // q, p) != 1 for q in prime_factors)


def find_primitive_root(p: int, prime_factors) -> int:
    for g in range(2, p):
        if is_primitive_root(g, p, prime_factors):
            return g
    raise ValueError("Không tìm thấy căn nguyên thủy")
