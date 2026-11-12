# sing-box DNS 体系与分流治理全景 (DNS & Routing)

> 汇集软路由防污染、防死锁、防绕过与 Dnsmasq 协作的完整工程标准。

---

## 一、 DNS 流量拓扑与处理模型

```
终端设备 (DHCP 获取网关 192.168.1.1:53)
   │
   ▼
[OpenWrt Dnsmasq] ──(解析 .lan/.local 内网主机名)──> 直接应答
   │ (外部域名查询或通过防火墙 DNAT 劫持)
   ▼
[sing-box TUN DNS 引擎]
   ├── 1. 内网/反向解析 (.lan / PTR) ───────> local-dns (127.0.0.1:53)
   ├── 2. Canary 域名阻断 (DoH / 私密代理) ──> reject (强制回退网关分流)
   ├── 3. 节点域名 (Bootstrap DNS) ─────────> alidns (223.5.5.5 直连解析)
   ├── 4. 国内白名单 (geosite:cn) ──────────> alidns (直连解析)
   └── 5. 境外被墙域名 ────────────────────> FakeIP (198.18.0.0/15) 或 远程加密 DoH
```

---

## 二、 六大核心治理与避坑约束

### 1. FakeIP vs RealIP 选型与反污染
* **FakeIP 模式 (推荐主力)**：
  - 本地直接分配 `198.18.0.0/15` 保留地址，100% 免疫 GFW 明文抢答投毒；
  - 域名在建立 TCP/UDP 连接时由远端代理节点发起真实解析，客户端 0 DNS 往返延迟。
* **RealIP 模式**：
  - 适合强依赖客户端获取境外真实 CDN IP 的场景；
  - 境外域名必须通过代理通道送往远端加密 DoH（`https://8.8.8.8/dns-query`）解析；
  - 必须包含 `"reverse_mapping": true`。

### 2. 节点域名解析死锁 (Bootstrap DNS Anti-Deadlock)
* 若节点地址为域名（如 `hk.example.com`），内核连接节点必须先解析该域名。
* **约束**：节点域名必须在 `dns.rules` 中显式指定 `server: "alidns"` 直连解析，并在 `route.rules` 中指定 `outbound: "direct"`，节点对象指定 `domain_resolver: "alidns"`，绝不允许走代理通道解析。

### 3. 浏览器 DoH 与 Apple 私密代理防绕过 (Canary Blocking)
* 客户端若开启 Firefox DoH 或 Apple Private Relay，会通过 443 端口加密隧道绕过网关分流。
* **约束**：在 `dns.rules` 与 `route.rules` 中 reject 以下三大约定 Canary 域名：
  - `use-application-dns.net`（Firefox 检测到阻断后自动关闭 DoH 并回退网关 DNS）
  - `mask.icloud.com` 与 `mask-h2.icloud.com`（Apple 设备检测到阻断后针对该 Wi-Fi 关闭 Private Relay）
  - 路由规则直接 reject 端口 853 (DoT) 与 STUN。

### 4. IPv6 AAAA 污染黑洞与手机国内 App 转圈假死根治
* **约束**：双重锁定纯净 IPv4：
  - sing-box 配置 `"strategy": "ipv4_only"`；
  - 运行 `setup_openwrt_network.sh` 在 Dnsmasq 中开启 `filter_aaaa='1'`，彻底根治淘宝/微信等国内 App 启动转圈假死。

### 5. 局域网主机名防劫持
* **约束**：`.lan`、`.local`、`router.lan`、`openwrt.lan` 以及内网 `PTR` 反向解析无条件路由至 `local-dns`，严禁为其分配 FakeIP。

### 6. Dnsmasq 循环死锁防护
* **约束**：Dnsmasq 不得将上游配置为指向 sing-box 本身（如 127.0.0.1:53），否则导致高频递归循环死锁。代理核心通过 TUN 劫持接管流量，Dnsmasq 保持原生默认配置即可。
