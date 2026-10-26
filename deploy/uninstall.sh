#!/usr/bin/env bash
# =====================================================================
#  Gỡ dịch vụ Ký số.   sudo bash deploy/uninstall.sh
#  Mặc định GIỮ LẠI thư mục cài đặt (có keys/: khóa bí mật, khóa CA).
# =====================================================================
set -euo pipefail

# ============================ CẤU HÌNH ===============================
APP_NAME="ky-so"
APP_USER="kyso"
APP_DIR="/opt/ky-so"
REMOVE_FILES="no"        # yes: xóa luôn $APP_DIR (MẤT toàn bộ khóa) và user hệ thống
# =====================================================================

[[ $EUID -eq 0 ]] || { echo "Hãy chạy bằng sudo." >&2; exit 1; }

systemctl disable --now "$APP_NAME" 2>/dev/null || true
rm -f "/etc/systemd/system/${APP_NAME}.service"
systemctl daemon-reload

if [[ -f "/etc/apache2/sites-available/${APP_NAME}.conf" ]]; then
  a2dissite -q "$APP_NAME" || true
  rm -f "/etc/apache2/sites-available/${APP_NAME}.conf"
  systemctl reload apache2 || true
fi

if [[ "$REMOVE_FILES" == "yes" ]]; then
  rm -rf "$APP_DIR"
  userdel "$APP_USER" 2>/dev/null || true
  echo "Đã gỡ dịch vụ, xóa $APP_DIR và user $APP_USER."
else
  echo "Đã gỡ dịch vụ. Thư mục $APP_DIR (gồm keys/) được giữ lại."
fi
