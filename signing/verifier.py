"""
Xác minh file đã ký:
  tách khối → kiểm tra vị trí → băm lại → verify chữ ký → xác thực danh tính
  (chứng chỉ do CA tin cậy cấp, hoặc dấu vân tay khóa tin cậy nhập tay).
"""
import base64

from mycrypto.sha256 import sha256
from .format import canonical_message, extract
from .keys import verify_with_spki, fingerprint, format_fingerprint, normalize_fingerprint
from . import pki


def verify_file(data: bytes, trusted_fingerprint: str = "") -> dict:
    """
    Trả về {"status", "checks", "details"}:
      status  — "valid" | "untrusted" | "invalid" | "unsigned"
      checks  — [{"ok": True/False/None, "text": ...}]   (None = cảnh báo)
      details — [[nhãn, giá trị], ...]
    """
    checks, details = [], []

    def check(ok, text):
        checks.append({"ok": ok, "text": text})

    found = extract(data)
    if found is None:
        return {"status": "unsigned", "checks": checks, "details": details}
    if found.block is None:
        check(False, found.error)
        return {"status": "invalid", "checks": checks, "details": details}

    m = found.block
    details += [["Người ký (tự khai)", m.get("signer", "")], ["Lý do", m.get("reason") or "(trống)"],
                ["Thời điểm (tự khai)", m.get("time", "")], ["Thuật toán", m.get("alg", "")],
                ["Giá trị băm đã ký", m.get("hash", "")]]
    identity = False   # đã xác thực được danh tính người ký hay chưa

    try:
        size = int(m["size"])
        # 1. Khối chữ ký phải nằm ngay sau phần đã ký, không có dữ liệu lạ phía sau
        check(found.offset == size,
              f"Khối chữ ký bắt đầu đúng tại byte {size}" if found.offset == size
              else f"Vị trí khối chữ ký ({found.offset}) khác kích thước đã ký ({size}): file đã bị chèn/cắt")
        if found.extra_bytes > 0:
            check(False, f"Có {found.extra_bytes} byte lạ sau khối chữ ký")

        # 2. Băm lại nội dung (toàn vẹn)
        h = sha256(data[:size]).hex()
        details.append(["Giá trị băm tính lại", h])
        check(h == m["hash"], "Giá trị băm khớp: nội dung không bị sửa" if h == m["hash"]
              else "Giá trị băm KHÔNG khớp: nội dung đã bị thay đổi")

        # 3. Kiểm tra chữ ký trên M
        spki = base64.b64decode(m["pub"])
        sig = base64.b64decode(m["sig"])
        ok = verify_with_spki(spki, canonical_message(m), sig)
        details.append(["Kích thước chữ ký / khóa công khai", f"{len(sig)} byte / {len(spki)} byte"])
        check(ok, "Chữ ký hợp lệ với khóa công khai đi kèm" if ok
              else "Chữ ký KHÔNG hợp lệ (σ hoặc siêu dữ liệu đã bị sửa)")

        fp = fingerprint(spki)
        details.append(["Dấu vân tay khóa trong file", format_fingerprint(fp)])

        # 4a. Chứng chỉ do CA cấp (PKI)
        cert = m.get("cert")
        if cert:
            details += [["Chứng chỉ: chủ thể", cert.get("subject", "")], ["Chứng chỉ: CA cấp", cert.get("issuer", "")],
                        ["Chứng chỉ: serial", cert.get("serial", "")]]
            results = pki.verify_certificate(cert, m["pub"], m.get("time"))
            for ok_c, text in results:
                check(ok_c, text)
            if all(r[0] for r in results):
                identity = True
                if cert.get("subject") != m.get("signer"):
                    check(None, f"Tên người ký tự khai \"{m.get('signer')}\" khác chủ thể chứng chỉ \"{cert.get('subject')}\". Tin theo chứng chỉ.")

        # 4b. Dấu vân tay nhập tay
        trusted = normalize_fingerprint(trusted_fingerprint)
        if trusted:
            match = trusted == fp
            check(match, "Khóa trùng dấu vân tay tin cậy" if match
                  else "Khóa KHÁC dấu vân tay tin cậy: có thể bị thay khóa")
            identity = identity or match

        if not identity and not cert and not trusted:
            check(None, "Không có chứng chỉ và chưa đối chiếu dấu vân tay: chưa biết ai thực sự đã ký")
    except Exception as e:  # khối chữ ký thiếu trường, DER hỏng, …
        check(False, f"Không xác minh được: {e}")

    if any(c["ok"] is False for c in checks):
        status = "invalid"
    elif not identity:
        status = "untrusted"
    else:
        status = "valid"
    return {"status": status, "checks": checks, "details": details}
