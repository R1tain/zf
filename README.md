# zf Port Forwarding Tool

`zf` 是一个基于 Linux 系统调用的端口转发工具，支持 TCP 和 UDP 转发，IPv4 和 IPv6，具备会话管理、超时清理和链路质量监控功能。

## 文件位置

- **日志文件位置**:
  - `/var/log/zf.log`
  - 记录会话状态、连接超时、链路延迟等信息。

- **会话文件位置**:
  - `/var/run/zf_sessions/`
  - 存储会话信息（`.session` 文件）和控制套接字（`.sock` 文件）。
  - 关闭会话后，`.session` 和 `.sock` 文件会被删除。

- **编译位置**:
  - 当前文件夹（执行 `install.sh` 的目录）
  - 源文件 `zf.c` 从 https://raw.githubusercontent.com/R1tain/zf/refs/heads/main/zf.c 下载并在此编译生成可执行文件 `zf`.

- **编译后文件位置**:
  - `/usr/local/bin/zf`
  - 编译后的可执行文件安装到此路径，可全局运行。

## 使用说明

1. **新建会话**:
   ```bash
   zf v4 0.0.0.0:8080 example.com:80 -p tcp,udp -c 30 -t 30
   ```
   - 转发 IPv4 的 TCP 和 UDP 流量到 `example.com:80`。
   - `-t 30`：30 秒空闲后关闭连接，主进程继续监听。
   - `-c 30`：每 30 秒检查远程主机连通性。
     - 若远程主机不响应，记录“连接远程主机失败”和“尝试重新连接...”，每 5 秒重试，直到恢复或会话终止。
     - 主进程继续运行，现有连接不受影响。

2. **查询会话**:
   ```bash
   zf -ls
   ```
   - 列出活动会话。

3. **关闭会话**:
   ```bash
   zf -k <session_id>
   ```
   - 终止指定会话，清理 `.session` 和 `.sock` 文件。

4. **显示帮助**:
   ```bash
   zf -h
   ```
   - 显示详细帮助信息，包括所有参数和示例。

## 注意事项

- **权限**:
  - 安装需 root 权限（`sudo ./install.sh`）。
  - 建议以低权限用户运行 `zf`（如 `sudo -u nobody zf ...`）。
  - ICMP 监控需要 `CAP_NET_RAW` 权限（由 `setcap` 设置）。

- **日志管理**:
  - 日志轮转已自动配置（`/etc/logrotate.d/zf`），每周轮转，保留 4 个备份，压缩旧日志。
  - 重复执行 `install.sh` 不会覆盖现有 `logrotate` 配置。

- **IPv6**:
  - 若使用 `-v6` 或 `-both`，确保系统和网络支持 IPv6.

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

## 编译和安装

运行以下命令编译和安装：
```bash
chmod +x install.sh
sudo ./install.sh
```

安装完成后，`zf` 可全局运行，日志和会话文件按上述路径存储。
