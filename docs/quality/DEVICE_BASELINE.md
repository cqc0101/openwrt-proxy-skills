# 软路由真机与仿真环境基线档案 (DEVICE_BASELINE)

## 1. 真机测试设备档案 (`tested`)

| 属性 | 记录值 |
| :--- | :--- |
| **设备标识** | `arm64-immortalwrt-gw01` |
| **CPU 架构** | `aarch64` (`ARMv8-A`) |
| **固件发行版** | `ImmortalWrt SNAPSHOT r0-3e24625` |
| **Linux 内核** | `6.18.44` (`HAS_BTF=0`, `HAS_TUN=1`, `NFQUEUE_OK=0`) |
| **内存与存储** | `RAM 495 MB` / `Overlay ROM 43.7 MB (可用 35.8 MB)` |
| **包管理器与防火墙** | `apk` (OpenWrt 25+ 主分支) / `fw4` (`nftables`) |
| **代理核心版本** | `sing-box-tiny 1.14.3` (`verified`), `dae v2.1.1` (因无 BTF 安全阻断验证通过) |
| **验证拓扑** | 二级从路由网关 (`br-lan=192.168.10.1`, `eth0=192.0.2.220` 上行私网 DHCP) |
| **证据文档** | [../validation-report.md](../validation-report.md) |

## 2. 容器与进程内仿真基线 (`simulated`)

| 仿真画像 | 固件代际 | 防火墙后端 | 包管理器 | 验证入口 |
| :--- | :--- | :--- | :--- | :--- |
| **Legacy OpenWrt** | `18.06 / 19.07 / 21.02` | `fw3` (`iptables`) | `opkg` | `tests/test_deploy_scripts.py` |
| **Modern OpenWrt** | `22.03 / 23.05 / 24.10` | `fw4` (`nftables`) | `opkg` | `docker/run_docker_tests.py --mode mock` |
| **Next-Gen ImmortalWrt** | `SNAPSHOT / 25+` | `fw4` (`nftables`) | `apk` | `docker/stress_test_matrix.py` |
