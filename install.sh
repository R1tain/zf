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
readonly README_FILE="$(pwd)/README.md" # 使用文档将生成在当前目录

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
    apt-get update -qq
    apt-get install -y -qq gcc libcap2-bin curl
}

# 下载并编译
compile_source() {
    log_info "正在从 ${COLOR_BLUE}${ZF_URL}${COLOR_RESET} 下载源码..."
    # 使用 curl 从 ZF_URL 变量指定的地址下载 zf.c
    curl -fsSL -o "$SRC_FILE" "$ZF_URL"

    log_info "正在编译 ${COLOR_CYAN}${SRC_FILE}${COLOR_RESET} (使用 -pthread)..."
    # 添加了 -pthread 标志来链接线程库
    gcc -o "$BIN_NAME" "$SRC_FILE" -Wall -pthread
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
    setcap cap_net_raw+ep "${BIN_DIR}/${BIN_NAME}" || log_warn "setcap 失败。ICMP 质量监控可能需要 root 权限运行。"

    configure_logrotate
    generate_readme # 调用函数生成使用说明文档
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
    notifempty
}
EOF
        chmod 644 "$LOGROTATE_CONF"
    fi
}

# 生成使用说明文档 (README.md)
generate_readme() {
    log_info "正在生成使用说明文档到当前目录: ${COLOR_CYAN}${README_FILE}${COLOR_RESET}..."
    local a='`' # For use in heredoc to avoid issues with backticks
    local code_block="${a}${a}${a}"

    cat > "$README_FILE" << EOF
# zf Port Forwarding Tool

\`zf\` 是一个基于 Linux 系统调用的端口转发工具，主要支持 TCP 转发，兼容 IPv4 和 IPv6，并具备会话管理、超时清理和基础的远程主机健康检查功能。

## 文件位置

- **可执行文件**:
  - \`${BIN_DIR}/${BIN_NAME}\`
  - 编译后的可执行文件安装到此路径，可全局运行。

- **日志文件**:
  - \`${LOG_FILE}\`
  - 记录程序运行状态、会话建立与关闭、连接超时、健康检查结果等信息。

- **会话管理目录**:
  - \`${SESSION_DIR}/\`
  - 存储活动会话的信息文件（\`.session\` 文件）和用于控制的套接字文件（\`.sock\` 文件）。
  - 当会话通过 \`zf -k <session_id>\` 或程序正常退出时，相关文件会被清理。

- **日志轮转配置**:
  - \`${LOGROTATE_CONF}\`
  - 用于管理 \`${LOG_FILE}\` 的自动轮转，防止日志文件过大。

## 使用说明

### 1. 启动新的转发会话

基本语法：
${code_block}bash
sudo zf <ip_version> <local_addr>:<local_port> <remote_addr>:<remote_port> [options]
${code_block}

**参数详解**:
- \`<ip_version>\`: IP 协议版本。
  - \`v4\`: 仅监听和转发 IPv4。
  - \`v6\`: 仅监听和转发 IPv6。
- \`<local_addr>:<local_port>\`: 本地监听的地址和端口。
  - 示例: \`0.0.0.0:8080\` (监听所有IPv4接口的8080端口), \`[::]:8080\` (监听所有IPv6接口的8080端口)。
- \`<remote_addr>:<remote_port>\`: 远程目标服务器的地址和端口。
  - 示例: \`example.com:80\`, \`192.168.1.100:443\`。
- \`[options]\`: 可选参数。
  - \`-p <protocol>\`: 转发的协议。当前稳定版本主要支持 \`tcp\` (这也是默认值)。
  - \`-c <interval>\`: 远程主机健康检查的间隔时间（秒）。默认30秒。若连续10次检查失败，会话将自动终止。
  - \`-t <timeout>\`: 连接空闲超时时间（秒）。默认300秒。如果一个已建立的转发连接在这个时间内没有任何数据活动，它将被关闭。

**示例**:
将所有进入本地IPv4地址的 \`33669\` 端口的TCP流量，转发到 \`103.214.23.219\` 服务器的 \`33669\` 端口，健康检查间隔60秒，连接超时180秒：
${code_block}bash
sudo zf v4 0.0.0.0:33669 103.214.23.219:33669 -c 60 -t 180
${code_block}

程序将作为守护进程在后台运行。会话ID和守护进程PID会在启动时打印到控制台。

### 2. 查询当前活动会话

${code_block}bash
zf -ls
${code_block}
该命令会列出所有当前正在运行的 \`zf\` 会话的配置信息，如ID, PID, 监听地址，目标地址等。
注意：在此版本的 `zf -ls` 输出中，"Note: Live stats are not available in this version." 表示实时的连接数和流量统计功能未包含。

### 3. 关闭指定会话

${code_block}bash
sudo zf -k <session_id>
${code_block}
- \`<session_id>\`: 通过 \`zf -ls\` 命令获取到的会话ID。
该命令会向指定的 \`zf\` 守护进程发送关闭信号，使其优雅地终止并清理相关资源。

### 4. 显示帮助信息

${code_block}bash
zf -h
zf -h --verbose
${code_block}
显示基本或详细的帮助信息，包括所有参数和用法说明。

## 注意事项

- **权限**:
  - 安装脚本 \`install.sh\` 和运行 \`zf -k\`，以及启动 \`zf\` 守护进程通常需要 \`sudo\` (root) 权限，因为需要操作 \`/usr/local/bin\`, \`/var/run\`, \`/var/log\`, \`/etc/logrotate.d\` 等目录，并且监听低于1024的端口也需要特权。
  - ICMP 健康检查功能（如果未来版本中包含更高级的ICMP探测）可能需要 \`CAP_NET_RAW\` 权限。安装脚本已尝试通过 \`setcap\` 为可执行文件赋予此权限。

- **日志管理**:
  - 日志轮转通过 \`/etc/logrotate.d/zf\` 文件自动配置，默认每周轮转，保留4个备份，并对旧日志进行压缩。

- **网络**:
  - 安装脚本需要访问互联网以下载 \`${SRC_FILE}\` 源码。
  - 确保防火墙规则允许相关的出入站连接。

## 安装与卸载

### 安装
1.  确保系统已安装 \`curl\`, \`gcc\`, \`libcap2-bin\`。脚本会自动尝试安装。
2.  下载 \`install.sh\` 脚本。
3.  赋予执行权限: \`chmod +x install.sh\`
4.  运行安装: \`sudo ./install.sh\`

### 卸载
运行以下命令进行卸载：
${code_block}bash
sudo ./install.sh uninstall
${code_block}
这将移除已安装的 \`${BIN_NAME}\` 二进制文件、logrotate配置文件和主日志文件。会话目录和旧的日志备份可能需要手动检查和删除。

## 清理编译文件
运行以下命令仅清理当前目录下载的源码和编译产生的临时文件：
${code_block}bash
./install.sh clean
${code_block}

---
EOF
}

# 停止所有正在运行的 zf 会话
stop_all_zf_sessions() {
    log_info "正在检查并停止所有正在运行的 ${COLOR_CYAN}zf${COLOR_RESET} 会话..."

    if command -v zf &> /dev/null; then
        log_info "尝试使用 '${COLOR_CYAN}zf -k${COLOR_RESET}' 优雅地关闭所有会话..."
        # 修正了从 zf -ls 输出中提取会话ID的命令
        SESSION_IDS=$(zf -ls 2>/dev/null | grep '^ID:' | awk '{print $2}' || true) # Suppress zf -ls errors if no sessions
        if [ -n "$SESSION_IDS" ]; then
            echo "$SESSION_IDS" | while read -r session_id; do
                if [ -n "$session_id" ]; then
                    log_info "正在关闭会话: ${COLOR_YELLOW}${session_id}${COLOR_RESET}"
                    # 使用 timeout 防止 zf -k 卡住
                    timeout 5s zf -k "$session_id" || log_warn "关闭会话 ${COLOR_YELLOW}${session_id}${COLOR_RESET} 失败，可能已被终止或超时。"
                fi
            done
        else
            log_info "未发现通过 'zf -ls' 枚举到的活动会话。"
        fi
        sleep 1
    fi

    if pgrep -x zf > /dev/null; then
        log_info "检测到残留 ${COLOR_CYAN}zf${COLOR_RESET} 进程，尝试优雅终止 (${COLOR_YELLOW}SIGTERM${COLOR_RESET})..."
        pkill zf 2>/dev/null || true # Allow command to fail if no process found
        sleep 2 # Give time for graceful shutdown

        if pgrep -x zf > /dev/null; then
            log_warn "优雅终止失败，强制终止 (${COLOR_RED}SIGKILL${COLOR_RESET})..."
            pkill -9 zf 2>/dev_null || true # Allow command to fail
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
    log_info "正在清理临时文件 (源码: ${COLOR_CYAN}${SRC_FILE}${COLOR_RESET})..."
    # 编译生成的可执行文件 BIN_NAME 在 install_files 中已被移动，此处无需清理
    rm -f "$SRC_FILE"
}

# 卸载功能
uninstall() {
    log_info "正在卸载 ${COLOR_CYAN}zf${COLOR_RESET}..."
    rm -f "${BIN_DIR}/${BIN_NAME}"
    rm -f "$LOGROTATE_CONF"
    # rm -f "$LOG_FILE" # 通常卸载时不删除主日志文件，用户可能需要保留
    log_info "二进制文件 ${COLOR_BLUE}${BIN_DIR}/${BIN_NAME}${COLOR_RESET} 已删除。"
    log_info "logrotate 配置文件 ${COLOR_BLUE}${LOGROTATE_CONF}${COLOR_RESET} 已删除。"
    log_warn "主日志文件 ${COLOR_BLUE}${LOG_FILE}${COLOR_RESET} 未删除，如有需要请手动处理。"
    log_warn "请手动检查并删除会话目录: ${COLOR_BLUE}${SESSION_DIR}${COLOR_RESET}"
    log_info "卸载完成。"
}

# 帮助信息
show_help() {
    echo -e "用法: ${COLOR_CYAN}$0 [install|uninstall|clean]${COLOR_RESET}"
    echo -e "  ${COLOR_YELLOW}install${COLOR_RESET}    (默认) 下载、编译并安装 zf，并生成使用说明。"
    echo -e "  ${COLOR_YELLOW}uninstall${COLOR_RESET}  卸载 zf 并移除相关配置。"
    echo -e "  ${COLOR_YELLOW}clean${COLOR_RESET}      仅清理当前目录下载的源码和编译产生的二进制文件。"
}

# --- 主逻辑 ---
main() {
    action=${1:-install} # Default action is install

    case "$action" in
        install)
            check_root
            stop_all_zf_sessions
            install_dependencies
            compile_source
            install_files # This function now also calls generate_readme
            cleanup
            log_info "${COLOR_GREEN}安装完成！${COLOR_RESET}"
            log_info "使用 '${COLOR_CYAN}zf -h${COLOR_RESET}' 查看帮助。"
            log_info "使用说明文档已生成到当前目录: ${COLOR_BLUE}${README_FILE}${COLOR_RESET}"
            log_info "使用 '${COLOR_CYAN}zf -ls${COLOR_RESET}' 查看会话，日志位于 ${COLOR_BLUE}${LOG_FILE}${COLOR_RESET}"
            ;;
        uninstall)
            check_root
            stop_all_zf_sessions # Stop before uninstalling
            uninstall
            ;;
        clean)
            # Cleanup doesn't need root, just cleans current dir
            cleanup
            log_info "正在清理当前目录编译产生的二进制文件 (${COLOR_CYAN}${BIN_NAME}${COLOR_RESET})..."
            rm -f "$(pwd)/$BIN_NAME" # Remove compiled binary if it exists in current dir
            log_info "清理完成。"
            ;;
        *)
            show_help
            ;;
    esac
}

# 执行主函数
main "$@"
