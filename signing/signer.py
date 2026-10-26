"""Ký file: băm → tạo M → ký → nhúng."""
import base64
from datetime import datetime, timezone

from mycrypto.sha256 import sha256
from .format import canonical_message, embed
from .keys import SigningKey

IMPL = {
    "RSA-PSS": "mycrypto.rsa: s = EM^d mod n, EMSA-PSS + CRT",
    "DSA": "mycrypto.dsa: r = (gᵏ mod p) mod q, s = k⁻¹(H + x·r) mod q",
    "ElGamal": "mycrypto.elgamal: r = αᵏ, s = k⁻¹(m − a·r) mod (p−1)",
}


def sign_file(content: bytes, key: SigningKey, filename: str, signer: str, reason: str,
              time: str = None, on_step=None):
    """
    Trả về (signed_bytes, block).
    on_step(title, value) — callback ghi lại từng bước để hiển thị.
    """
    step = on_step or (lambda *_: None)
    meta = {
        "v": 1,
        "alg": key.label,
        "filename": filename,
        "signer": signer or "(khong ten)",
        "reason": reason or "",
        "time": time or datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }
    step("Đọc file gốc", f"{filename} · {len(content)} B")

    meta["hash"] = sha256(content).hex()
    meta["size"] = len(content)
    step("Băm nội dung: h = SHA-256(F')  [mycrypto.sha256]", meta["hash"])

    M = canonical_message(meta)
    step("Tạo thông điệp chuẩn hóa M (băm + siêu dữ liệu)", M.decode().replace("\n", " ‖ "))

    sig = key.sign(M)
    step(f"Ký: σ = Sign(sk, M) · {len(sig)} byte  [{IMPL[key.alg]}]", sig.hex())

    block = {**meta, "pub": base64.b64encode(key.spki).decode(), "sig": base64.b64encode(sig).decode()}
    if key.cert:
        block["cert"] = key.cert
        step("Đính kèm chứng chỉ do CA cấp", f"subject = {key.cert['subject']} · serial {key.cert['serial']}")
    signed = embed(content, block)
    step("Nhúng khối chữ ký vào cuối file",
         f"F_signed = F' ({len(content)} B) ‖ khối chữ ký ({len(signed) - len(content)} B)")
    return signed, block


def signed_filename(name: str) -> str:
    """hop-dong.pdf → hop-dong.signed.pdf"""
    dot = name.rfind(".")
    return name[:dot] + ".signed" + name[dot:] if dot > 0 else name + ".signed"
