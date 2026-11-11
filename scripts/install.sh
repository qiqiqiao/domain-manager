#!/usr/bin/env bash
set -euo pipefail

# Domain Manager installation helper for Linux AMD64.
# Usage: sudo ./scripts/install.sh [path-to-binary]
# The service runs as the "domain-manager" system user and listens on
# 127.0.0.1:10120 by default. Put a TLS reverse proxy in front for remote access.

BINARY="${1:-dist/domain-manager-linux-amd64}"
INSTALL_DIR="/opt/domain-manager"
SERVICE="/etc/systemd/system/domain-manager.service"

if [[ ! -f "$BINARY" ]]; then
  echo "binary not found: $BINARY" >&2
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "please run as root" >&2
  exit 1
fi

if ! id domain-manager >/dev/null 2>&1; then
  useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin domain-manager
fi

install -d -m 0750 -o domain-manager -g domain-manager "$INSTALL_DIR"
install -m 0755 -o root -g root "$BINARY" "$INSTALL_DIR/domain-manager"
install -d -m 0700 -o domain-manager -g domain-manager "$INSTALL_DIR/data" "$INSTALL_DIR/logs" "$INSTALL_DIR/configs"
if [[ ! -f "$INSTALL_DIR/configs/config.yaml" ]]; then
  CONFIG_SRC="$(cd "$(dirname "$0")/.." && pwd)/configs/config.example.yaml"
  if [[ -f "$CONFIG_SRC" ]]; then
    install -m 0600 -o domain-manager -g domain-manager "$CONFIG_SRC" "$INSTALL_DIR/configs/config.yaml"
  else
    cat > "$INSTALL_DIR/configs/config.yaml" <<'YAML'
server:
  host: 127.0.0.1
  port: 10120
  mode: release
  cookie_secure: false
  trusted_proxies: ["127.0.0.1"]
  read_timeout_seconds: 30
  write_timeout_seconds: 60
  max_upload_mb: 100

data_dir: ./data
log_dir: ./logs
database_path: ./data/domain-manager.db
log_level: info
YAML
    chown domain-manager:domain-manager "$INSTALL_DIR/configs/config.yaml"
    chmod 0600 "$INSTALL_DIR/configs/config.yaml"
  fi
fi

install -m 0644 "$(dirname "$0")/domain-manager.service" "$SERVICE"
systemctl daemon-reload
systemctl enable domain-manager
systemctl restart domain-manager

echo "Domain Manager installed."
echo "The service listens on 127.0.0.1:10120. Configure an HTTPS reverse proxy for remote access."
echo "The initial admin password is written to:"
echo "  $INSTALL_DIR/data/initial-admin-password (mode 0600)"
echo "Delete that file after the first login. Logs: journalctl -u domain-manager -f"
