# 环境探测（第一轮）

型号 NanoPi R2S；固件 ImmortalWrt 25.12.2 r38135-0c4cd0f9920a；内核 6.12.103；aarch64_generic；BusyBox 1.37.0。内存 1000512 KiB，基线可用约 837716 KiB，无 swap。根文件系统 ext4 约 290 MiB，可用约 181 MiB；/tmp 为约 488 MiB tmpfs。APK 3.0.5，初始已安装 184 个包。

管理口 eth0 WAN（DHCP）；LAN br-lan/eth1 无载波；DHCP 租约为空。IPv4 默认路由为上级路由，IPv6 无公网默认路由。DNS 为 dnsmasq 2.93，上游取自 DHCP。原生 dae 2.1.1 已运行，BTF 已挂载；sing-box、Python、jq、curl、socat、ipset、iptables 未安装，/dev/net/tun 缺失。防火墙为 fw4/nftables，已有 WAN 入站 ACCEPT，软件/硬件流量分载均关闭。

证据：ENV-001/002/003、PROBE-001、DOCTOR-DAE-001、DOCTOR-SING-001、DNS-001、BACKUP-001。原始探测含私有网络标识，公开交付时需脱敏。ENV-001 的 CRLF 与 ip -br 不兼容属于测试工具问题，已用 ENV-002 纠正。

SSH 采取首次接触信任并固定主机密钥，未声称完成带外指纹核验。完整 /etc 备份已下载并核对 SHA-256（约 5.4 MB）。此为第一轮采集时的状态；后续已执行接管、热重载及恢复，结果见 FINAL-REPORT.md。
