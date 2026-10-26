"""
Định dạng khối chữ ký nhúng (tương thích bản JavaScript):

    F_signed = F' ‖ b"\\n%DSIG-BEGIN " ‖ Base64(JSON) ‖ b" %DSIG-END" ‖ b"\\n"
    JSON     = { v, alg, hash, size, filename, signer, reason, time, pub, sig }

F' (size byte đầu) là phần được băm và ký. Khối chữ ký nằm ngoài vùng được ký.
"""
import base64
import json
from dataclasses import dataclass
from typing import Optional

import config


def canonical_message(m: dict) -> bytes:
    """
    Thông điệp chuẩn hóa M được ký. Gồm giá trị băm và toàn bộ siêu dữ liệu,
    nên không thể đổi người ký / lý do / thời điểm mà giữ nguyên chữ ký.
    """
    fields = [config.FORMAT_VERSION, m["alg"], m["hash"], str(m["size"]),
              m["filename"], m["signer"], m["reason"], m["time"]]
    return "\n".join(fields).encode("utf-8")


def build_trailer(block: dict) -> bytes:
    payload = base64.b64encode(json.dumps(block, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    return config.MARKER_BEGIN + payload + config.MARKER_END + config.TRAILER_END


def embed(content: bytes, block: dict) -> bytes:
    return content + build_trailer(block)


@dataclass
class Extracted:
    offset: int                 # vị trí byte bắt đầu MARKER_BEGIN
    block: Optional[dict]
    extra_bytes: int            # số byte lạ sau khối chữ ký (phải = 0)
    error: str = ""


def extract(data: bytes) -> Optional[Extracted]:
    """Tìm khối chữ ký cuối cùng trong file."""
    win_start = max(0, len(data) - config.TRAILER_SEARCH_WINDOW)
    window = data[win_start:]
    b = window.rfind(config.MARKER_BEGIN)
    if b < 0:
        return None
    e = window.find(config.MARKER_END, b)
    if e < 0:
        return None
    end_abs = win_start + e + len(config.MARKER_END) + len(config.TRAILER_END)
    result = Extracted(offset=win_start + b, block=None, extra_bytes=len(data) - end_abs)
    try:
        payload = window[b + len(config.MARKER_BEGIN):e]
        result.block = json.loads(base64.b64decode(payload, validate=True).decode("utf-8"))
    except Exception:
        result.error = "Khối chữ ký hỏng: không giải mã được Base64/JSON"
    return result
