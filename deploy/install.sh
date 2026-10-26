#!/usr/bin/env bash
# =====================================================================
#  Cài Ký số thành dịch vụ systemd trên Ubuntu (Gunicorn + tùy chọn Apache2)
#
#  Cách dùng (chạy từ thư mục gốc project):
#      sudo bash deploy/install.sh
#  Chạy lại lệnh trên để cập nhật code; khóa trong keys/ được giữ nguyên.
# =====================================================================
set -euo pipefail

# ============================ CẤU HÌNH ===============================
APP_NAME="ky-so"                 # tên dịch vụ systemd: ky-so.service
APP_USER="kyso"                  # user hệ thống chạy dịch vụ (không có shell)
APP_DIR="/opt/ky-so"             # thư mục cài đặt
BIND_HOST="0.0.0.0"              # 0.0.0.0: máy khác truy cập trực tiếp; 127.0.0.1: chỉ qua Apache trên cùng máy
BIND_PORT="8000"                 # cổng Gunicorn
OPEN_FIREWALL="yes"              # yes: mở BIND_PORT trên UFW (nếu UFW đang bật)
ALLOW_FROM="192.168.1.0/24"      # chỉ cho mạng LAN này truy cập; để trống = mọi địa chỉ (không khuyến nghị)
WORKERS="2"                      # số tiến trình Gunicorn
TIMEOUT="120"                    # giây; lần đầu tạo khóa DSA phải sinh tham số (5–30 s)
PREGEN_DSA_PARAMS="yes"          # yes: sinh sẵn tham số DSA lúc cài (5–30 s)

# --- Apache2 reverse proxy (tùy chọn) ---
USE_APACHE="no"                  # yes: tạo VirtualHost proxy tới Gunicorn
DOMAIN="kyso.example.com"        # ServerName
SSL_CERT=""                      # để trống: chỉ tạo vhost :80
SSL_KEY=""                       # ví dụ chứng chỉ Cloudflare Origin: /etc/ssl/cf/origin.pem + .key
UPLOAD_LIMIT_MB="6"              # giới hạn body ở Apache (>= MAX_UPLOAD_MB trong config.py)
# =====================================================================

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mLỖI:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Hãy chạy bằng sudo."
[[ -f "$SRC_DIR/app.py" && -d "$SRC_DIR/mycrypto" ]] || die "Không thấy app.py trong $SRC_DIR"

# ---------------------------------------------------------------- 1. Gói hệ thống
log "Cài gói hệ thống (python3-venv, rsync, curl)"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv rsync curl >/dev/null

# ---------------------------------------------------------------- 2. User hệ thống
if ! id "$APP_USER" &>/dev/null; then
  log "Tạo user hệ thống $APP_USER"
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
fi

# ---------------------------------------------------------------- 3. Chép mã nguồn
log "Chép mã nguồn vào $APP_DIR (giữ nguyên keys/)"
mkdir -p "$APP_DIR"
rsync -a --delete \
  --exclude '.venv/' --exclude '__pycache__/' --exclude '*.pyc' \
  --exclude 'keys/' --exclude '.git/' --exclude 'docs/bao-cao/' \
  "$SRC_DIR/" "$APP_DIR/"
mkdir -p "$APP_DIR/keys"

# ---------------------------------------------------------------- 4. Môi trường Python
log "Tạo virtualenv và cài Flask + Gunicorn"
[[ -x "$APP_DIR/.venv/bin/python" ]] || python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt" gunicorn

# ---------------------------------------------------------------- 5. Quyền thư mục
# Mã nguồn: root sở hữu, user dịch vụ chỉ đọc. keys/: chỉ user dịch vụ đọc/ghi.
chown -R root:root "$APP_DIR"
chmod -R u=rwX,go=rX "$APP_DIR"
chown -R "$APP_USER:$APP_USER" "$APP_DIR/keys"
chmod 700 "$APP_DIR/keys"
find "$APP_DIR/keys" -type f -name '*.json' -exec chmod 600 {} +

# ---------------------------------------------------------------- 6. Khởi tạo CA (và tham số DSA)
# Làm trước khi chạy nhiều worker, để các worker không tạo CA cùng lúc.
log "Khởi tạo CA demo (sinh khóa RSA-PSS 2048 nếu chưa có)"
( cd "$APP_DIR" && runuser -u "$APP_USER" -- .venv/bin/python -c "from signing import pki; pki.load_ca()" )
if [[ "$PREGEN_DSA_PARAMS" == "yes" ]]; then
  log "Sinh sẵn tham số DSA (2048, 256) — có thể mất 5–30 giây"
  ( cd "$APP_DIR" && runuser -u "$APP_USER" -- .venv/bin/python -c "from signing import keys; keys.domain_params()" )
fi

# ---------------------------------------------------------------- 7. Dịch vụ systemd
log "Ghi $SERVICE_FILE"
sed -e "s|@APP_NAME@|$APP_NAME|g" -e "s|@APP_USER@|$APP_USER|g" -e "s|@APP_DIR@|$APP_DIR|g" \
    -e "s|@BIND@|$BIND_HOST:$BIND_PORT|g" -e "s|@WORKERS@|$WORKERS|g" -e "s|@TIMEOUT@|$TIMEOUT|g" \
    "$SRC_DIR/deploy/ky-so.service" > "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable "$APP_NAME" >/dev/null
systemctl restart "$APP_NAME"

# Đợi dịch vụ lên rồi kiểm tra
for _ in {1..20}; do
  if curl -fsS -o /dev/null "http://127.0.0.1:$BIND_PORT/"; then break; fi
  sleep 0.5
done
curl -fsS -o /dev/null "http://127.0.0.1:$BIND_PORT/" \
  || die "Dịch vụ không phản hồi. Xem: journalctl -u $APP_NAME -n 50"
log "Dịch vụ $APP_NAME đang chạy tại http://$BIND_HOST:$BIND_PORT"

# ---------------------------------------------------------------- 7b. Tường lửa UFW (tùy chọn)
if [[ "$BIND_HOST" != "127.0.0.1" && "$OPEN_FIREWALL" == "yes" ]] && command -v ufw >/dev/null \
   && ufw status | grep -q "Status: active"; then
  if [[ -n "$ALLOW_FROM" ]]; then
    log "UFW: cho phép $ALLOW_FROM truy cập cổng $BIND_PORT/tcp"
    ufw allow from "$ALLOW_FROM" to any port "$BIND_PORT" proto tcp comment "$APP_NAME" >/dev/null
  else
    log "UFW: mở cổng $BIND_PORT/tcp cho mọi địa chỉ"
    ufw allow "$BIND_PORT/tcp" comment "$APP_NAME" >/dev/null
  fi
fi
SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ "$BIND_HOST" != "127.0.0.1" ]] && log "Từ máy khác, mở: http://${SERVER_IP:-<IP-máy-chủ>}:$BIND_PORT"

# ---------------------------------------------------------------- 8. Apache2 (tùy chọn)
if [[ "$USE_APACHE" == "yes" ]]; then
  log "Cấu hình Apache2 reverse proxy cho $DOMAIN"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apache2 >/dev/null
  a2enmod -q proxy proxy_http headers >/dev/null
  SITE="/etc/apache2/sites-available/${APP_NAME}.conf"
  LIMIT=$(( UPLOAD_LIMIT_MB * 1024 * 1024 ))
  sed -e "s|@DOMAIN@|$DOMAIN|g" -e "s|@BACKEND@|http://127.0.0.1:$BIND_PORT/|g" \
      -e "s|@LIMIT@|$LIMIT|g" -e "s|@TIMEOUT@|$TIMEOUT|g" -e "s|@APP_NAME@|$APP_NAME|g" \
      "$SRC_DIR/deploy/apache-ky-so.conf" > "$SITE"
  if [[ -n "$SSL_CERT" && -n "$SSL_KEY" ]]; then
    a2enmod -q ssl >/dev/null
    sed -e "s|@DOMAIN@|$DOMAIN|g" -e "s|@BACKEND@|http://127.0.0.1:$BIND_PORT/|g" \
        -e "s|@LIMIT@|$LIMIT|g" -e "s|@TIMEOUT@|$TIMEOUT|g" -e "s|@APP_NAME@|$APP_NAME|g" \
        -e "s|@SSL_CERT@|$SSL_CERT|g" -e "s|@SSL_KEY@|$SSL_KEY|g" \
        "$SRC_DIR/deploy/apache-ky-so-ssl.conf" >> "$SITE"
  fi
  a2ensite -q "$APP_NAME" >/dev/null
  apachectl configtest
  systemctl reload apache2
  log "Apache2 đã proxy http://$DOMAIN → 127.0.0.1:$BIND_PORT"
fi

cat <<EOF

Hoàn tất.
  Trạng thái : systemctl status $APP_NAME
  Nhật ký    : journalctl -u $APP_NAME -f
  Khởi động lại sau khi sửa code: sudo bash deploy/install.sh
  Gỡ cài đặt : sudo bash deploy/uninstall.sh
EOF
