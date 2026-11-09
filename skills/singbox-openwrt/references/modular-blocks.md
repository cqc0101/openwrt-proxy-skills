# sing-box 模块化规则积木与复杂拓扑组装指南

> 本文档为 AI Agent 提供**配置原子化组装能力**。Agent 不应受限于固定死板的静态模板，而应根据用户的真实网络拓扑（主路由、旁路由、多 WAN、指定设备分流、AdGuardHome 联动），像拼积木一样组合出 100% 贴合用户意图的高可用生产配置。

---

## 一、 五大正交核心积木 (Orthogonal Building Blocks)

完整的 sing-box 软路由网关由五个相互解耦的模块拼装而成：

```
┌────────────────────────────────────────────────────────┐
│ 1. inbounds (入站): TUN 网关 / SOCKS / Mixed 本地端口  │
├────────────────────────────────────────────────────────┤
│ 2. outbounds (出站): proxy 策略组 / auto 优选 / 节点池 │
├────────────────────────────────────────────────────────┤
│ 3. dns (解析): hosts -> 直连上游 -> 加密上游 -> FakeIP │
├────────────────────────────────────────────────────────┤
│ 4. route (路由): 接口防环 -> 规则集 -> 多维分流规则   │
├────────────────────────────────────────────────────────┤
│ 5. experimental (运行): /tmp 闪存保护缓存 + Clash API  │
└────────────────────────────────────────────────────────┘
```

---

## 二、 复杂网络拓扑定制配方 (Topological Recipes)

### 配方 A：标准主路由模式 (Main Gateway)
**适用场景**：软路由作为光猫拨号路由或一级网关，具备独立物理 WAN 口与 LAN 口。

```json
{
  "route": {
    "auto_detect_interface": true,
    "default_domain_resolver": "alidns"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun0",
      "address": "172.19.0.1/30",
      "auto_route": true,
      "strict_route": false,
      "auto_redirect": false
    }
  ]
}
```
> **排坑要点**：若路由器内核缺失 `nfqueue` 模块（导致国内直连全 RST），Agent 应将 `"auto_detect_interface": true` 替换为 `"default_interface": "eth0"`（或真实物理 WAN 网卡名）。

---

### 配方 B：单网口旁路由模式 (Bypass Gateway / 单臂透明网关)
**适用场景**：主路由（如 `192.168.1.1`）负责拨号和 DHCP，软路由（如 `192.168.1.2`）只有单根网线接入局域网交换机，部分设备手动将网关设为 `192.168.1.2`。

#### 1. 致命缺陷预防（非对称路由丢包）
在旁路由拓扑中，客户端发出的请求：`客户端 -> 旁路由 -> 代理出口`；如果请求直连：`旁路由 -> 主路由 -> 客户端`，导致客户端收到未被旁路由 NAT 的源 IP 数据包，客户端操作系统直接 RST 丢弃！
**Agent 核心决策**：
1. 必须在 OpenWrt 防火墙 LAN 区域开启 IP 动态伪装（`masquerade: 1`），推荐直接运行最后一公里脚本：
   ```bash
   sh setup_openwrt_network.sh --bypass
   # 或底层动态查找 LAN 区域并开启伪装：
   # LAN_IDX=$(uci show firewall | grep -E "\.name='lan'|\.name='LAN'" | head -n1 | cut -d'.' -f2)
   # uci set firewall.${LAN_IDX}.masquerade='1' && uci commit firewall && /etc/init.d/firewall reload
   ```
2. 在 sing-box 的 `route.rules` 首部必须放行到主路由自身 IP 的直连：
   ```json
   {
     "ip_cidr": ["192.168.1.1/32"],
     "outbound": "direct"
   }
   ```

---

### 配方 C：特定局域网设备按 IP / MAC 精准分流 (Device Splitting)
**适用场景**：
- 用户要求：“家里的智能电视/AppleTV 必须走美区，国内扫地机器人/NAS 坚决直连，我的开发工作站走代理”。

**Agent 组装规则**：
在 `route.rules` 的 sniff 与 hijack-dns 之后，插入设备 IP 专属分流：
```json
{
  "route": {
    "rules": [
      { "action": "sniff" },
      {
        "type": "logical",
        "mode": "or",
        "rules": [{ "protocol": "dns" }, { "port": 53 }],
        "action": "hijack-dns"
      },
      {
        "source_ip_cidr": ["192.168.1.50/32", "192.168.1.51/32"],
        "outbound": "direct"
      },
      {
        "source_ip_cidr": ["192.168.1.100/32"],
        "outbound": "proxy"
      }
    ]
  }
}
```

---

### 配方 D：AdGuardHome / SmartDNS 外部去广告共存 (DNS Cascading)
**适用场景**：软路由已安装 AdGuardHome（监听 `127.0.0.1:53` 或 `5335`）做全屋去广告。

**Agent 组装规则**：
1. 将 sing-box 本地 DNS 服务的上游指向 AdGuardHome：
   ```json
   {
     "tag": "local-adg",
     "type": "udp",
     "server": "127.0.0.1",
     "server_port": 5335
   }
   ```
2. 国内分流规则指向 `local-adg`，境外被墙域名直接走 `google-dns` 或 `fakeip-dns`，避免外部 DNS 遭受污染同时享受去广告。

---

### 配方 E：浏览器 DoH 与 Apple 私密代理防绕过 (Canary Blocking)
**适用场景**：局域网客户端启用 Firefox DoH、Chrome 安全 DNS 或 iOS / macOS iCloud 私密代理，绕过网关 DNS 导致国内 CDN 降速或访问异常。

**Agent 组装规则**：
在 `dns.rules` 与 `route.rules` 中显式添加 Canary 域名阻断：
```json
{
  "domain": [
    "use-application-dns.net",
    "mask.icloud.com",
    "mask-h2.icloud.com"
  ],
  "action": "reject"
}
```
> **原理**：Firefox 探测到 `use-application-dns.net` 被阻断（NXDOMAIN）后自动降级关闭内置 DoH；Apple 设备探测到 `mask.icloud.com` 被阻断后自动针对当前 Wi-Fi 关闭 Private Relay，促使终端 100% 遵循软路由网关的高性能防污染分流。

---

## 三、 Agent 组装与交付闭环规范

当用户提出定制需求时，Agent 的执行闭环应当遵循：
1. **意图分析**：确定用户网络拓扑（主路由 vs 旁路由，网段是 192.168.1.x 还是其他）；
2. **积木拼接**：基于基准 Schema 动态组装特定 `inbounds`、`outbounds`、`dns` 与 `route`；
3. **静态门控验证**：将生成的配置传给 `check_config.py`，必须 0 报错；
4. **安全推送与部署**：通过 SSH 管道将配置写入远端 `/tmp/config.json.test`，经 `sing-box check` 校验通过后原子替换并重启服务；
5. **最后一公里闭环**：调用 `setup_openwrt_network.sh` 确保系统级防火墙、MSS 钳制与 Dnsmasq 妥善接管。
