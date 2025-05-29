#!/usr/bin/env bash
set -euo pipefail

BIN_NAME="zf"
SRC_FILE="zf.c"
INSTALL_DIR="/usr/local/bin"
SESSION_DIR="/var/run/zf_sessions"
LOG_FILE="/var/log/zf.log"

echo "[INFO] Checking for root privileges..."
[[ $(id -u) -eq 0 ]] || { echo "[ERROR] Please run as root." >&2; exit 1; }

echo "[INFO] Checking for ${SRC_FILE} ..."
[[ -f ${SRC_FILE} ]] || { echo "[ERROR] ${SRC_FILE} not found." >&2; exit 1; }

echo "[INFO] Installing build toolchain ..."
apt-get -qq update
DEBIAN_FRONTEND=noninteractive apt-get -qq install -y build-essential

echo "[INFO] Compiling ${SRC_FILE} ..."
BUILD_DIR=$(mktemp -d)
gcc -O2 -Wall -Wextra -pthread -o "${BUILD_DIR}/${BIN_NAME}" "${SRC_FILE}"

echo "[INFO] Installing to ${INSTALL_DIR} ..."
install -m 755 -b -T "${BUILD_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
rm -rf "${BUILD_DIR}"

echo "[INFO] Ensuring session dir & log file ..."
install -d -m 700 "${SESSION_DIR}"
touch "${LOG_FILE}" && chmod 644 "${LOG_FILE}"

echo "[SUCCESS] ${BIN_NAME} installed at ${INSTALL_DIR}/${BIN_NAME}"

