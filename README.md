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
  - 源文件 `zf.c` 在此编译生成可执行文件 `zf`。

- **编译后文件位置**:
  - `/usr/local/bin/zf`
  - 编译后的可执行文件安装到此路径，可全局运行。

## 使用说明

1. **新建会话**:
   ```bash
   zf v4 0.0.0.0:8080 example.com:80 -p tcp,udp -c 30 -t 30
   ```
   - 转发 IPv4 的 TCP 和 UDP 流量到 `example.com:80`。
   - `-t 30` 表示 30 秒空闲后关闭连接，但主进程继续监听。
   - `-c 30` 表示每 30 秒检查远程主机连通性。

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

## 注意事项

- **权限**:
  - 安装需 root 权限（`sudo ./install.sh`）。
  - 建议以低权限用户运行 `zf`（如 `sudo -u nobody zf ...`）。
  - ICMP 监控需要 `CAP_NET_RAW` 权限（由 `setcap` 设置）。

- **日志管理**:
  - 建议配置 logrotate 清理 `/var/log/zf.log`：
    ```bash
    sudo nano /etc/logrotate.d/zf
    ```
    添加：
    ```
    /var/log/zf.log {
        weekly
        rotate 4
        compress
        missingok
    }
    ```

- **IPv6**:
  - 若使用 `-v6` 或 `-both`，确保系统和网络支持 IPv6。

- **环境**:
  - 测试于 Ubuntu 22.04，确保 `gcc` 和 `libcap2-bin` 已安装。
  - 内核版本需高于 3.7（支持 `TCP_FASTOPEN`，若不支持自动禁用）。

## 编译和安装

运行以下命令编译和安装：
```bash
chmod +x install.sh
sudo ./install.sh
```

安装完成后，`zf` 可全局运行，日志和会话文件按上述路径存储。
