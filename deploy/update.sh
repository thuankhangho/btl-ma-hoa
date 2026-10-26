#!/usr/bin/env bash
# =====================================================================
#  Chép file code Ký số từ thư mục git hiện tại vào thư mục dịch vụ
#
#  Cách dùng (chạy từ thư mục gốc project):
#      bash deploy/update.sh        # tự gọi sudo khi cần
#  Chỉ chép code; không đụng tới keys/, .venv/ và không khởi động lại dịch vụ.
# =====================================================================
set -euo pipefail

# ============================ CẤU HÌNH ===============================
APP_DIR="/opt/ky-so"             # thư mục dịch vụ, phải khớp với install.sh
# File/thư mục cần để chạy app.py (wsgi.py là điểm vào của Gunicorn)
RUNTIME_PATHS=(app.py config.py wsgi.py requirements.txt signing mycrypto templates static)
# =====================================================================

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mLỖI:\033[0m %s\n' "$*" >&2; exit 1; }

# Chưa phải root thì chạy lại chính script này bằng sudo
if [[ $EUID -ne 0 ]]; then
  exec sudo bash "${BASH_SOURCE[0]}" "$@"
fi

cd "$SRC_DIR"
for p in "${RUNTIME_PATHS[@]}"; do
  [[ -e "$p" ]] || die "Không thấy $p trong $SRC_DIR"
done

log "Chép code từ $SRC_DIR vào $APP_DIR"
mkdir -p "$APP_DIR"
rsync -a --relative --itemize-changes --chown=root:root --chmod=u=rwX,go=rX \
  --exclude '__pycache__/' --exclude '*.pyc' \
  "${RUNTIME_PATHS[@]}" "$APP_DIR/" | sed 's/^/    /'

log "Xong. Khởi động lại dịch vụ để áp dụng: sudo systemctl restart ky-so"
