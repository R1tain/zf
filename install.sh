#!/bin/bash

# 脚本在任何命令失败时立即退出
set -e
# 尝试使用未定义的变量时报错
set -u

# --- 全局变量定义 ---
readonly ZF_URL="https://raw.githubusercontent.com/R1tain/zf/refs/heads/main/zf.c"
readonly SRC_FILE="zf.c"
readonly BIN_NAME="zf"
readonly INSTALL_PREFIX="/usr/local"
readonly BIN_DIR="${INSTALL_PREFIX}/bin"
readonly SESSION_DIR="/var/run/zf_sessions"
readonly LOG_FILE="/var/log/zf.log"
readonly LOGROTATE_CONF="/etc/logrotate.d/zf"
readonly README_FILE="$(pwd)/README.md"

# --- 颜色定义 ---
readonly COLOR_RESET='\033[0m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[0;33m'
readonly COLOR_RED='\033[0;31m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'

# --- 函数定义 ---

# 日志函数
log_info() {
    echo -e "${COLOR_GREEN}[INFO]${COLOR_RESET} $1"
}

log_warn() {
    echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $1"
}

log_error() {
    # 错误信息输出到 stderr
    echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $1" >&2
    exit 1
}

# 检查是否为 root 用户
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "此脚本需要 root 权限运行。请使用 '${COLOR_CYAN}sudo ./install.sh${COLOR_RESET}'"
    fi
}

# 安装依赖
install_dependencies() {
    log_info "正在检查并安装依赖 (${COLOR_CYAN}gcc, libcap2-bin, curl${COLOR_RESET})..."
    if ! command -v apt-get &> /dev/null; then
        log_error "此脚本目前仅支持基于 Debian/Ubuntu 的系统 (使用 apt)。"
    fi
    apt-get update
    apt-get install -y gcc libcap2-bin curl
}

# 下载并编译
compile_source() {
    log_info "正在从 ${COLOR_BLUE}${ZF_URL}${COLOR_RESET} 下载源码..."
    # 修正点：在文件操作命令中，使用原始变量名，而不是带颜色的版本
    curl -fsSL -o "$SRC_FILE" "$ZF_URL"

    log_info "正在编译 ${COLOR_CYAN}${SRC_FILE}${COLOR_RESET}..."
    gcc -o "$BIN_NAME" "$SRC_FILE" -Wall
}

# 安装文件和配置
install_files() {
    log_info "正在安装 ${COLOR_CYAN}${BIN_NAME}${COLOR_RESET} 到 ${COLOR_BLUE}${BIN_DIR}${COLOR_RESET}..."
    mkdir -p "$BIN_DIR"
    mv "$BIN_NAME" "$BIN_DIR/"
    chmod +x "${BIN_DIR}/${BIN_NAME}"

    log_info "正在创建会话目录 ${COLOR_BLUE}${SESSION_DIR}${COLOR_RESET}..."
    mkdir -p "$SESSION_DIR"
    chmod 755 "$SESSION_DIR"

    log_info "正在创建和设置日志文件 ${COLOR_BLUE}${LOG_FILE}${COLOR_RESET}..."
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"

    log_info "正在为 ${COLOR_CYAN}zf${COLOR_RESET} 设置 ICMP 权限..."
    setcap cap_net_raw+ep "${BIN_DIR}/${BIN_NAME}"

    configure_logrotate
    generate_readme
}

# 配置日志轮转
configure_logrotate() {
    if [ -f "$LOGROTATE_CONF" ]; then
        log_warn "logrotate 配置文件已存在，跳过生成: ${COLOR_BLUE}${LOGROTATE_CONF}${COLOR_RESET}"
    else
        log_info "正在配置 logrotate..."
        cat > "$LOGROTATE_CONF" << 'EOF'
/var/log/zf.log {
    weekly
    rotate 4
    compress
    missingok
}
EOF
        chmod 644 "$LOGROTATE_CONF"
    fi
}

# 生成说明文档 (已更新为最新内容)
generate_readme() {
    log_info "正在生成说明文档 ${COLOR_CYAN}README.md${COLOR_RESET}..."
    local a='`'
    local code_block="${a}${a}${a}"

    cat > "$README_FILE" << EOF
# zf Port Forwarding Tool

\`zf\` 是一个基于 Linux 系统调用的端口转发工具，支持 TCP 和 UDP 转发，IPv4 和 IPv6，具备会话管理、超时清理和链路质量监控功能。

## 文件位置

- **日志文件位置**:
  - \`/var/log/zf.log\`
  - 记录会话状态、连接超时、链路延迟等信息。

- **会话文件位置**:
  - \`/var/run/zf_sessions/\`
  - 存储会话信息（\`.session\` 文件）和控制套接字（\`.sock\` 文件）。
  - 关闭会话后，\`.session\` 和 \`.sock\` 文件会被删除。

- **编译位置**:
  - 当前文件夹（执行 \`install.sh\` 的目录）
  - 源文件 \`zf.c\` 从 https://raw.githubusercontent.com/R1tain/zf/refs/heads/main/zf.c 下载并在此编译生成可执行文件 \`zf\`.

- **编译后文件位置**:
  - \`/usr/local/bin/zf\`
  - 编译后的可执行文件安装到此路径，可全局运行。

## 使用说明

1. **新建会话**:
   ${code_block}bash
   zf v4 0.0.0.0:8080 example.com:80 -p tcp,udp -c 30 -t 30
   ${code_block}
   - 转发 IPv4 的 TCP 和 UDP 流量到 \`example.com:80\`。
   - \`-t 30\`：30 秒空闲后关闭连接，主进程继续监听。
   - \`-c 30\`：每 30 秒检查远程主机连通性。
     - 若远程主机不响应，记录“连接远程主机失败”和“尝试重新连接...”，每 5 秒重试，直到恢复或会话终止。
     - 主进程继续运行，现有连接不受影响。

2. **查询会话**:
   ${code_block}bash
   zf -ls
   ${code_block}
   - 列出活动会话。

3. **关闭会话**:
   ${code_block}bash
   zf -k <session_id>
   ${code_block}
   - 终止指定会话，清理 \`.session\` 和 \`.sock\` 文件。

4. **显示帮助**:
   ${code_block}bash
   zf -h
   ${code_block}
   - 显示详细帮助信息，包括所有参数和示例。

## 注意事项

- **权限**:
  - 安装需 root 权限（\`sudo ./install.sh\`）。
  - 建议以低权限用户运行 \`zf\`（如 \`sudo -u nobody zf ...\`）。
  - ICMP 监控需要 \`CAP_NET_RAW\` 权限（由 \`setcap\` 设置）。

- **日志管理**:
  - 日志轮转已自动配置（\`/etc/logrotate.d/zf\`），每周轮转，保留 4 个备份，压缩旧日志。
  - 重复执行 \`install.sh\` 不会覆盖现有 \`logrotate\` 配置。

- **IPv6**:
  - 若使用 \`-v6\` 或 \`-both\`，确保系统和网络支持 IPv6.

- **网络**:
  - 安装需要访问 https://raw.githubusercontent.com/R1tain/zf/refs/heads/main/zf.c 下载 \`zf.c\`。
  - 若网络受限，可配置代理：
    ${code_block}bash
    export http_proxy=http://<proxy>:<port>
    export https_proxy=http://<proxy>:<port>
    ${code_block}

- **环境**:
  - 测试于 Ubuntu 22.04，确保 \`gcc\`、\`libcap2-bin\` 和 \`curl\` 已安装。
  - 内核版本需高于 3.7（支持 \`TCP_FASTOPEN\`，若不支持自动禁用）。

## 编译和安装

运行以下命令编译和安装：
${code_block}bash
chmod +x install.sh
sudo ./install.sh
${code_block}

安装完成后，\`zf\` 可全局运行，日志和会话文件按上述路径存储。
EOF
}

# 停止所有正在运行的 zf 会话
stop_all_zf_sessions() {
    log_info "正在检查并停止所有正在运行的 ${COLOR_CYAN}zf${COLOR_RESET} 会话..."

    if command -v zf &> /dev/null; then
        log_info "尝试使用 '${COLOR_CYAN}zf -k${COLOR_RESET}' 优雅地关闭所有会话..."
        zf -ls | awk 'NR>1 {print $1}' | while read -r session_id; do
            if [ -n "$session_id" ]; then
                log_info "正在关闭会话: ${COLOR_YELLOW}${session_id}${COLOR_RESET}"
                zf -k "$session_id" || log_warn "关闭会话 ${COLOR_YELLOW}${session_id}${COLOR_RESET} 失败，可能已被终止。"
            fi
        done
        sleep 1
    fi

    if pgrep -x zf > /dev/null; then
        log_info "检测到残留 ${COLOR_CYAN}zf${COLOR_RESET} 进程，尝试优雅终止 (${COLOR_YELLOW}SIGTERM${COLOR_RESET})..."
        pkill zf 2>/dev/null
        sleep 2

        if pgrep -x zf > /dev/null; then
            log_warn "优雅终止失败，强制终止 (${COLOR_RED}SIGKILL${COLOR_RESET})..."
            pkill -9 zf 2>/dev/null
            sleep 1
        fi
    fi

    if pgrep -x zf > /dev/null; then
        log_error "无法终止所有 ${COLOR_CYAN}zf${COLOR_RESET} 进程，请手动检查！"
    else
        log_info "所有 ${COLOR_CYAN}zf${COLOR_RESET} 进程已成功清理。"
    fi
}

# 清理临时文件
cleanup() {
    log_info "正在清理临时文件 (${COLOR_CYAN}${SRC_FILE}, ${BIN_NAME}${COLOR_RESET})..."
    rm -f "$SRC_FILE" "$BIN_NAME"
}

# 卸载功能
uninstall() {
    log_info "正在卸载 ${COLOR_CYAN}zf${COLOR_RESET}..."
    rm -f "${BIN_DIR}/${BIN_NAME}"
    rm -f "$LOGROTATE_CONF"
    rm -f "$LOG_FILE"
    log_warn "二进制文件和配置文件已删除。"
    log_warn "请手动检查并删除会话目录: ${COLOR_BLUE}${SESSION_DIR}${COLOR_RESET}"
    log_warn "旧的日志文件可能仍然存在于 ${COLOR_BLUE}/var/log/${COLOR_RESET} 中。"
    log_info "卸载完成。"
}

# 帮助信息
show_help() {
    echo -e "用法: ${COLOR_CYAN}$0 [install|uninstall|clean]${COLOR_RESET}"
    echo -e "  ${COLOR_YELLOW}install${COLOR_RESET}    (默认) 下载、编译并安装 zf。"
    echo -e "  ${COLOR_YELLOW}uninstall${COLOR_RESET}  卸载 zf 并移除相关配置。"
    echo -e "  ${COLOR_YELLOW}clean${COLOR_RESET}      仅清理当前目录的临时文件。"
}

# --- 主逻辑 ---
main() {
    action=${1:-install}

    case "$action" in
        install)
            check_root
            stop_all_zf_sessions
            install_dependencies
            compile_source
            install_files
            cleanup
            log_info "${COLOR_GREEN}安装完成！${COLOR_RESET}"
            log_info "使用 '${COLOR_CYAN}zf -ls${COLOR_RESET}' 查看会话，日志位于 ${COLOR_BLUE}${LOG_FILE}${COLOR_RESET}"
            log_info "说明文档已生成：${COLOR_BLUE}${README_FILE}${COLOR_RESET}"
            ;;
        uninstall)
            check_root
            stop_all_zf_sessions
            uninstall
            ;;
        clean)
            cleanup
            ;;
        *)
            show_help
            ;;
    esac
}

# 执行主函数
main "$@"
