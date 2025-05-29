#!/usr/bin/env bash
set -euo pipefail

BIN_NAME="zf"
SRC_FILE="zf.c"
SRC_URL="https://raw.githubusercontent.com/R1tain/zf/main/zf.c"
INSTALL_DIR="/usr/local/bin"
SESSION_DIR="/var/run/zf_sessions"
LOG_FILE="/var/log/zf.log"
LOGROTATE_FILE="/etc/logrotate.d/zf"

echo "[INFO] Root check..."
[[ $(id -u) -eq 0 ]] || { echo "[ERROR] Run as root."; exit 1; }

# --- 1. 获取源码 -------------------------------------------------
if [[ -f ${SRC_FILE} ]]; then
    echo "[INFO] Found local ${SRC_FILE}"
else
    echo "[INFO] ${SRC_FILE} not found, downloading..."
    curl -fsSL "${SRC_URL}" -o "${SRC_FILE}" || {
        echo "[ERROR] Failed to download ${SRC_URL}" >&2; exit 1; }
fi

# --- 2. 安装依赖 -------------------------------------------------
echo "[INFO] Installing build toolchain & logrotate ..."
apt-get -qq update
DEBIAN_FRONTEND=noninteractive apt-get -qq install -y build-essential logrotate curl

# --- 3. 编译 -----------------------------------------------------
echo "[INFO] Compiling ${SRC_FILE} ..."
BUILD_DIR=$(mktemp -d)
gcc -O2 -Wall -Wextra -pthread -o "${BUILD_DIR}/${BIN_NAME}" "${SRC_FILE}"

# --- 4. 安装 -----------------------------------------------------
echo "[INFO] Installing binary to ${INSTALL_DIR} ..."
install -m 755 -b -T "${BUILD_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
rm -rf "${BUILD_DIR}"

# --- 5. 运行目录 / 日志 -----------------------------------------
echo "[INFO] Preparing runtime directories ..."
install -d -m 700 "${SESSION_DIR}"
touch "${LOG_FILE}" && chmod 644 "${LOG_FILE}"

echo "[INFO] Setting up logrotate (keep 3 days) ..."
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

echo "[SUCCESS] zf installed at ${INSTALL_DIR}/${BIN_NAME}"
