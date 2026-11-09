# OpenWrt 避坑指南与智能排障手册 (Pitfalls & Troubleshooting)

> 汇集 OpenWrt 软路由透明代理中最容易引发“断网、假死、无网络”的物理层、内核层与网络层核心坑点。

---

## 一、 五大物理与网络层致命坑点

### 1. fw4 (nftables) 防火墙丢包（最常见）
* **现象**：sing-box 进程显示运行，但局域网电脑手机完全无法上网。
* **病因**：OpenWrt 22.03+ (fw4) 默认 DROP 所有未在防火墙区域声明的虚拟网卡流量转发。
* **解法**：动态定位 LAN 区域并将 `tun0` 加入设备列表，设置 `forward=ACCEPT`：
  ```bash
  # 运行最后一公里网络闭环工具：
  sh setup_openwrt_network.sh
  ```

### 2. PPPoE 宽带大包握手黑洞 (MSS Clamping 缺失)
* **现象**：能 ping 通海外 IP、小网页能开，但 Google、YouTube、GitHub 登录时 TLS Client Hello 大包卡死转圈。
* **病因**：光猫桥接 PPPoE 拨号导致 MTU 为 1492，加上 sing-box TUN 开销，导致大报文超出 MTU 被路由器静默丢弃（Path MTU 黑洞）。
* **解法**：在 LAN 区域开启 MSS 钳制：`uci set firewall.@zone[LAN].mtu_fix='1' && /etc/init.d/firewall reload`（`setup_openwrt_network.sh` 已全自动处理）。

### 3. 单网口旁路由非对称路由丢包 (Asymmetric Routing Drop)
* **现象**：客户端手动配了旁路由为网关，网页打不开或频繁 TCP RST。
* **病因**：客户端发送请求经旁路由发往直连主路由，主路由回复报文直接发给客户端，客户端收到未经旁路由 NAT 的源 IP 数据包后直接拒绝。
* **解法**：在旁路由防火墙 LAN 开启动态伪装：`uci set firewall.@zone[LAN].masq='1'`（或运行 `setup_openwrt_network.sh --bypass`）。

### 4. 缺失 nfqueue 内核模块直连自捕获
* **现象**：出海正常，但国内百度、淘宝直连全部 Connection Reset。
* **病因**：部分 MT7981 / Snapshot 固件内核缺失 `nfqueue`，sing-box `auto_detect_interface` 自保机制失效，导致国内直连流量被 TUN 自身循环捕获。
* **解法**：生成配置时必须指定 `--wan-iface <WAN接口名>`（如 `eth0` 或 `pppoe-wan`），显式将直连流量锁定在物理 WAN。

### 5. SPI 闪存写穿变砖
* **现象**：路由器运行数月后死机，重启无法开机、配置无法保存。
* **病因**：`experimental.cache_file.path` 未配置，默认高频刷写到 `/etc` 或 `/overlay` 物理闪存芯片。
* **解法**：严格锁定 `experimental.cache_file.path: "/tmp/sing-box-cache.db"`（挂载于 RAM）。

---

## 二、 症状 → 病因 → 自愈行动矩阵 (Diagnostic Matrix)

| 症状特征 | 核心病因 | Agent 自主修复行动 |
| :--- | :--- | :--- |
| `sing-box restart` 进程不启动 | procd 服务默认被禁用或非 root 无权建 tun0 | `uci set sing-box.main.enabled='1' && uci set sing-box.main.user='root' && uci commit sing-box` |
| `sing-box check` 报 schema error | 混用了 1.13 与 1.14 专属字段 | 参照 `architecture-and-schema.md` 修正字段 |
| 局域网访问 `router.lan` 报 404 | 内网私有域名被 FakeIP 误劫持 | 在 `dns.rules` 中将 `.lan/.local` 送至 `local-dns` |
| 微信/淘宝国内 App 刷新转圈 | 宽带无 IPv6 但返回了 AAAA 记录 | 运行 `setup_openwrt_network.sh` 开启 `filter_aaaa=1` |
| 终端无法出海且提示证书错误 | 软路由时钟与真实时间偏差 >90s | 执行 `ntpd -q -p ntp.aliyun.com` 校准系统时间 |
| 启动日志显示 ruleset timeout | 国内直连拉取 GitHub 规则集超时 | 生成配置时指定 `--mirror jsdelivr` 镜像加速 |
