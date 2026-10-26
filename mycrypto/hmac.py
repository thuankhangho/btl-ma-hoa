"""HMAC-SHA256 theo RFC 2104:  HMAC(K, m) = H((K' ⊕ opad) ‖ H((K' ⊕ ipad) ‖ m))"""
from .sha256 import sha256, BLOCK_SIZE


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    if len(key) > BLOCK_SIZE:
        key = sha256(key)
    key = key.ljust(BLOCK_SIZE, b"\x00")
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5C for k in key)
    return sha256(opad + sha256(ipad + msg))
