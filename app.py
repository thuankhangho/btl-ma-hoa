"""
Web demo ký số — Flask (chỉ làm web server; toàn bộ mật mã nằm trong mycrypto/, tự cài đặt).

    GET  /              trang Ký số
    GET  /api/keys      danh sách khóa (chỉ phần công khai)
    POST /api/keys      sinh cặp khóa + CA cấp chứng chỉ     {alg, owner}
    POST /api/sign      ký file (multipart)                   file, key_id, signer, reason
    POST /api/verify    xác minh file (multipart)             file, trusted_fp
    GET  /api/ca        thông tin CA demo + danh sách thu hồi
    POST /api/revoke    thu hồi chứng chỉ                      {serial}
"""
import base64
import time

from flask import Flask, jsonify, render_template, request

import config
from signing import keys, pki
from signing.signer import sign_file, signed_filename
from signing.verifier import verify_file

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_MB * 1024 * 1024
app.config["TEMPLATES_AUTO_RELOAD"] = True      # sửa template không cần khởi động lại server
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0     # trình duyệt luôn lấy CSS/JS mới nhất


def _error(msg, code=400):
    return jsonify({"error": msg}), code


@app.errorhandler(413)
def too_large(_):
    return _error(f"File vượt quá {config.MAX_UPLOAD_MB} MB (giới hạn trong config.py)", 413)


@app.get("/")
def index():
    return render_template("index.html", cfg=config, algorithms=keys.ALGORITHMS)


# ===================================================================== khóa, CA
@app.get("/api/keys")
def api_list_keys():
    return jsonify([k.public_info() for k in keys.list_keys()])


@app.post("/api/keys")
def api_generate_key():
    body = request.get_json(silent=True) or {}
    alg = body.get("alg", config.DEFAULT_ALGORITHM)
    owner = (body.get("owner") or config.DEFAULT_SIGNER).strip()
    if alg not in keys.ALGORITHMS:
        return _error("Thuật toán không hỗ trợ")
    t = time.perf_counter()
    key = keys.generate(alg, owner)
    key.cert = pki.issue(owner, key.spki, key.label)
    keys.save(key)
    info = key.public_info()
    info["elapsed_ms"] = round((time.perf_counter() - t) * 1000)
    return jsonify(info)


@app.get("/api/ca")
def api_ca():
    return jsonify(pki.ca_info())


@app.post("/api/revoke")
def api_revoke():
    serial = (request.get_json(silent=True) or {}).get("serial", "")
    if not serial.isalnum():
        return _error("Serial không hợp lệ")
    pki.revoke(serial)
    return jsonify(pki.ca_info())


# ===================================================================== ký, xác minh
@app.post("/api/sign")
def api_sign():
    f = request.files.get("file")
    if not f or not f.filename:
        return _error("Chưa chọn file")
    try:
        key = keys.load(request.form.get("key_id", ""))
    except (OSError, ValueError, KeyError):
        return _error("Không tìm thấy khóa. Hãy tạo cặp khóa mới.")

    content = f.read()
    steps = []
    t = time.perf_counter()
    signed, block = sign_file(
        content, key, f.filename,
        signer=request.form.get("signer", "").strip(),
        reason=request.form.get("reason", "").strip(),
        on_step=lambda title, value: steps.append([title, value]),
    )
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    return jsonify({
        "filename": signed_filename(f.filename),
        "signed_b64": base64.b64encode(signed).decode(),
        "sig_json": block,
        "steps": steps,
        "elapsed_ms": round((time.perf_counter() - t) * 1000),
        "zip_warning": ext in config.ZIP_BASED_EXTENSIONS,
    })


@app.post("/api/verify")
def api_verify():
    f = request.files.get("file")
    if not f:
        return _error("Chưa chọn file")
    t = time.perf_counter()
    result = verify_file(f.read(), request.form.get("trusted_fp", ""))
    result["elapsed_ms"] = round((time.perf_counter() - t) * 1000)
    return jsonify(result)


if __name__ == "__main__":
    print(f"Mở http://{config.HOST}:{config.PORT}")
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
