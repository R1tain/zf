#!/usr/bin/env bash
set -euo pipefail

BIN_NAME="zf"
SRC_FILE="zf.c"
INSTALL_DIR="/usr/local/bin"
SESSION_DIR="/var/run/zf_sessions"
LOG_FILE="/var/log/zf.log"
LOGROTATE_FILE="/etc/logrotate.d/zf"

echo "[INFO] Root check..."
[[ $(id -u) -eq 0 ]] || { echo "[ERROR] Run as root."; exit 1; }

echo "[INFO] Checking ${SRC_FILE} ..."
[[ -f ${SRC_FILE} ]] || { echo "[ERROR] ${SRC_FILE} not found."; exit 1; }

echo "[INFO] Installing build toolchain ..."
apt-get -qq update
DEBIAN_FRONTEND=noninteractive apt-get -qq install -y build-essential logrotate

echo "[INFO] Building ${SRC_FILE} ..."
BUILD_DIR=$(mktemp -d)
gcc -O2 -Wall -Wextra -pthread -o "${BUILD_DIR}/${BIN_NAME}" "${SRC_FILE}"

echo "[INFO] Installing binary to ${INSTALL_DIR} ..."
install -m 755 -b -T "${BUILD_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
rm -rf "${BUILD_DIR}"

echo "[INFO] Preparing runtime directories ..."
install -d -m 700 "${SESSION_DIR}"
touch "${LOG_FILE}" && chmod 644 "${LOG_FILE}"

echo "[INFO] Setting up logrotate ..."
cat > "${LOGROTATE_FILE}" <<EOF
${LOG_FILE} {
    daily
    rotate 3
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF

echo "[SUCCESS] zf installed at ${INSTALL_DIR}/${BIN_NAME} with logrotate (3 days retention)"
