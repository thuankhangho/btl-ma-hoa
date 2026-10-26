"""
Mã hóa/giải mã DER tối giản cho khóa công khai SubjectPublicKeyInfo (SPKI, RFC 5280).

    SPKI ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }

    RSA      { rsaEncryption, NULL }                 BIT STRING = SEQ { INT n, INT e }   (RFC 3279)
    DSA      { id-dsa, SEQ { INT p, INT q, INT g } } BIT STRING = INT y               (RFC 3279)
    ElGamal  { elGamal (OIW), SEQ { INT p, INT α } } BIT STRING = INT β
"""
import base64

TAG_INTEGER, TAG_BIT_STRING, TAG_NULL, TAG_OID, TAG_SEQUENCE = 0x02, 0x03, 0x05, 0x06, 0x30


# ---------------------------------------------------------------- OID
def encode_oid(dotted: str) -> bytes:
    """Mã hóa OID (X.690 8.19): hai số đầu gộp 40·a + b, mỗi số còn lại viết base-128, bit 8 = 1 nếu còn tiếp."""
    parts = [int(x) for x in dotted.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for n in parts[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7F))
            n >>= 7
        out += bytes(reversed(chunk))
    return bytes(out)


OID_RSA_ENCRYPTION = encode_oid("1.2.840.113549.1.1.1")
OID_DSA = encode_oid("1.2.840.10040.4.1")
OID_ELGAMAL = encode_oid("1.3.14.7.2.1.1")


# ---------------------------------------------------------------- mã hóa
def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def integer(x: int) -> bytes:
    b = x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b      # thêm 0x00 để không bị hiểu là số âm
    return tlv(TAG_INTEGER, b)


def sequence(*items: bytes) -> bytes:
    return tlv(TAG_SEQUENCE, b"".join(items))


def bit_string(data: bytes) -> bytes:
    return tlv(TAG_BIT_STRING, b"\x00" + data)   # 0 bit thừa


def oid(value: bytes) -> bytes:
    return tlv(TAG_OID, value)


def spki_rsa(n: int, e: int) -> bytes:
    return sequence(sequence(oid(OID_RSA_ENCRYPTION), tlv(TAG_NULL, b"")),
                    bit_string(sequence(integer(n), integer(e))))


def spki_dsa(p: int, q: int, g: int, y: int) -> bytes:
    return sequence(sequence(oid(OID_DSA), sequence(integer(p), integer(q), integer(g))),
                    bit_string(integer(y)))


def spki_elgamal(p: int, alpha: int, beta: int) -> bytes:
    return sequence(sequence(oid(OID_ELGAMAL), sequence(integer(p), integer(alpha))),
                    bit_string(integer(beta)))


def read_tlv(data: bytes, pos: int = 0):
    """Đọc một phần tử TLV tại pos, trả về (tag, value, vị trí kế tiếp)."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(data[pos:pos + nbytes], "big")
        pos += nbytes
    value = data[pos:pos + length]
    if len(value) != length:
        raise ValueError("DER bị cắt cụt")
    return tag, value, pos + length


def _expect(data, pos, tag):
    t, v, nxt = read_tlv(data, pos)
    if t != tag:
        raise ValueError(f"DER: cần tag {tag:#x}, gặp {t:#x}")
    return v, nxt


def _ints(data: bytes, count: int):
    out, pos = [], 0
    for _ in range(count):
        v, pos = _expect(data, pos, TAG_INTEGER)
        out.append(int.from_bytes(v, "big"))
    return out


def parse_spki(der: bytes):
    """
    Trả về một trong:  ("RSA", n, e)   ("DSA", (p, q, g), y)   ("ElGamal", (p, α), β)
    """
    body, _ = _expect(der, 0, TAG_SEQUENCE)
    alg, pos = _expect(body, 0, TAG_SEQUENCE)
    key_bits, _ = _expect(body, pos, TAG_BIT_STRING)
    alg_oid, apos = _expect(alg, 0, TAG_OID)
    key = key_bits[1:]   # bỏ byte "số bit thừa"

    if alg_oid == OID_RSA_ENCRYPTION:
        seq, _ = _expect(key, 0, TAG_SEQUENCE)
        n, e = _ints(seq, 2)
        return "RSA", n, e

    if alg_oid in (OID_DSA, OID_ELGAMAL):
        params, _ = _expect(alg, apos, TAG_SEQUENCE)
        (y,) = _ints(key, 1)
        if alg_oid == OID_ELGAMAL:
            return "ElGamal", tuple(_ints(params, 2)), y
        return "DSA", tuple(_ints(params, 3)), y

    raise ValueError("Thuật toán khóa không hỗ trợ")


def to_pem(der: bytes, label: str = "PUBLIC KEY") -> str:
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----"
