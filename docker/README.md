# OpenWrt 本地测试环境 (Docker & Mock)

本目录为 `skills/singbox-openwrt` 与 `skills/dae-openwrt` 技能提供免真机的本地自动化测试基座。
支持在完全不触碰、不影响生产软路由硬件的前提下，验证探针探测、配置生成、UCI 防火墙注入、服务拉起与 7 步全链路健康诊断。

## 架构概览

```
[ 测试调用方 (run_docker_tests.py / .ps1) ]
                 │
   ┌─────────────┴─────────────┐
   ▼                           ▼
【Docker 容器模式】       【本地 Mock 仿真模式】
(openwrt/rootfs:x86-64)    (纯 Python SSH/UCI 仿真)
  ├─ Dropbear SSH :22        ├─ 兼容 Paramiko SSH :2222
  ├─ uci / fw4 防火墙        ├─ 动态响应探针与诊断指令
  ├─ sing-box 1.14.3 核心    ├─ 内置 JSON 语法与连通校验
  └─ 暴露 2222 与 9090       └─ 0 秒极速冷启，无虚拟化依赖
```

## 快速上手

### 1. 自动模式（推荐）

自动探测本地 Docker 守护进程。若 Docker 已就绪则构建并运行真实容器；若 Docker 守护进程离线（如刚启用 Hyper-V 尚未重启系统），则平滑降级至本地 Mock 仿真模式：

```bash
python docker/run_docker_tests.py
```

或使用 PowerShell 脚本：

```powershell
.\docker\run_docker_tests.ps1
```

### 2. 强制使用本地 Mock 模式（秒级响应、免 Docker）

```bash
python docker/run_docker_tests.py --mode mock
```

### 3. 强制使用 Docker 容器模式

```bash
python docker/run_docker_tests.py --mode docker
```

亦可使用标准 Docker Compose 启动容器后手动交互：

```bash
cd docker
docker compose up -d --build
ssh -p 2222 root@127.0.0.1
# 默认密码: password
```

## 测试覆盖流水线

每次运行将依次执行以下 5 大阶段：

1. **探针采集 (Probe)**：执行 `probe.ps1` / `probe.sh`，采集架构 (`x86_64`)、OpenWrt 版本 (`23.05.5`)、防火墙 (`fw4`)、WAN/LAN 网卡绑定；
2. **配置生成 (Auto Config)**：调用 `auto_config.py`，根据探针事实动态选择 `openwrt-1.14-tun-fakeip.json` 模板并注入测试节点；
3. **防火墙放行 (Firewall)**：调用 `setup_openwrt_network.sh`，将 `tun0` 放行至 LAN 区域 (`@zone[0]`)；
4. **服务部署 (Deploy)**：安全下发配置至 `/etc/sing-box/config.json`，校验语法并重启 `sing-box` procd 服务；
5. **全链路诊断 (Diagnose)**：运行 7 步健康诊断，验证进程 PID、TUN 接口、防火墙放行、Clash API 端口 (9090)、DNS 路由与内存配额。

## 文件清单

- `Dockerfile.openwrt`：基于 `openwrt/rootfs` 官方镜像定制的 OpenWrt 测试镜像
- `entrypoint.sh`：容器入口脚本，自动初始化 Dropbear 密钥与 TUN 虚拟设备
- `docker-compose.yml`：标准 Docker Compose 编排文件
- `mock_openwrt_server.py`：轻量高仿真 OpenWrt SSH 测试服务端（纯 Python 实现）
- `run_docker_tests.py`：跨平台自动化测试运行器
- `run_docker_tests.ps1`：PowerShell 自动化测试运行器
