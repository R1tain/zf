# zf – Secure / Stable Port-Forwarding Daemon

`zf` 是一个基于 Linux 系统调用的端口转发工具，支持 TCP 和 UDP 转发，IPv4 和 IPv6，具备会话管理、超时清理和链路质量监控功能。


> **Build**
> ```bash
> gcc -O2 -Wall -Wextra -pthread -o zf zf.c
> ```

---

## 接口简介

```text
zf v4|v6|all [<addr>:]port <remote_host:port> [options]
```

| 参数 (必选)          | 说明                                                                                                         |
|----------------------|--------------------------------------------------------------------------------------------------------------|
| `v4` / `v6` / `all`  | 监听栈类型：<br>• **v4** → 仅 IPv4 <br>• **v6** → 仅 IPv6 <br>• **all** → 双栈 (单 IPv6 socket，收 IPv4-mapped) |
| `[<addr>:]port`      | 本地监听。仅写 `port` → IPv4 默认 `0.0.0.0`，IPv6/双栈默认 `::`.                                              |
| `<remote_host:port>` | 远端目标。IPv6 地址可写 `[2001:db8::1]:80`.                                                                   |

### 参数详情

| 选项                    | 默认 | 说明                                                   |
|-------------------------|------|--------------------------------------------------------|
| `-p tcp\|udp\|all`      | tcp  | 转发协议：仅 TCP、仅 UDP、或二者皆有 (`all`)           |
| `-c <sec>`              | 30   | 远端健康检查周期（秒）                                 |
| `-t <sec>`              | 300  | 空闲连接超时（秒，TCP 子进程）                         |
| `-ls`                   | —    | 列出当前会话                                           |
| `-k <session_id>`       | —    | 终止指定会话                                           |
| `-h`                    | —    | 显示帮助                                               |

---

## 快速示例

### 1 双栈 + TCP 转发
```bash
zf all 8080 example.com:80
```
* 监听 `0.0.0.0:8080` 与 `[::]:8080`
* 所有 TCP 流量 → `example.com:80`

### 2 仅 IPv4，TCP + UDP
```bash
zf v4 5353 224.0.0.251:5353 -p all
```

### 3 仅 IPv6 + UDP
```bash
zf v6 6000 [2001:db8::1]:6000 -p udp
```

---

## 管理命令

```bash
# 查看会话
zf -ls

# 终止会话
zf -k <ID>
```

*`<ID>` 由 zf 启动时打印，格式 `stack_port-timestamp`，如 `all_8080-1748501300`.*

---

## 日志与会话文件

| 路径                                               | 说明                                   |
|----------------------------------------------------|----------------------------------------|
| `/var/log/zf.log`                                  | 运行日志（logrotate：每日，保留 3 天） |
| `/var/run/zf_sessions/<ID>.session`                | 会话元数据（文本）                     |
| `/var/run/zf_sessions/<ID>.sock`                   | 控制套接字（用于 `-k`）                |

---

## 安装脚本（示例）

```bash
sudo bash install.sh     # 自动编译、安装、配置 logrotate
```

脚本会将可执行文件安装到 `/usr/local/bin/zf` 并创建日志轮转规则。


## 注意事项


- **网络**:
  - 安装需要访问 https://raw.githubusercontent.com/R1tain/zf/refs/heads/main/zf.c 下载 `zf.c`。
  - 若网络受限，可配置代理：
    ```bash
    export http_proxy=http://<proxy>:<port>
    export https_proxy=http://<proxy>:<port>
    ```

- **环境**:
  - 测试于 Ubuntu 22.04，确保 `gcc`、`libcap2-bin` 和 `curl` 已安装。
  - 内核版本需高于 3.7（支持 `TCP_FASTOPEN`，若不支持自动禁用）。



安装完成后，`zf` 可全局运行，日志和会话文件按上述路径存储。
