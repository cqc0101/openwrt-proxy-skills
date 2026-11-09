# dae 规则语法、五大铁律与模块化组装指南

> 本指南将 dae eBPF 官方规范浓缩为 AI Agent 可直接理解和组装的紧凑规则体系，消除多级文档冗余。

---

## 一、 dae 语义与拓扑五大铁律 (Golden Rules)

1. **单引号词法规范**：
   除 `ext:"xxx.dat:tag"` 外部文件引用外，所有包含冒号 `:`、斜杠 `/`、正则或复合协议的字符串，统一使用单引号 `'...'` 包裹（如 `tcp_check_url: 'http://cp.cloudflare.com'`）。
2. **must_direct 宿主防环铁律**：
   dae 默认拦截所有发往 53 端口的请求。`dnsmasq`、`odhcpd`、`netifd`、`uhttpd` 的 53 端口流量必须在 `routing {}` 首行放行：
   ```shell
   pname(dnsmasq, odhcpd, netifd, uhttpd) && l4proto(udp) && dport(53) -> must_direct
   ```
3. **布尔取反 (!) 合并铁律**：
   两行独立的 `!` 规则在 dae 中为 OR 语义。表达“既不属于 A 也不属于 B”必须合并写在同一行内：
   ```shell
   !domain(geosite:a, geosite:b) -> my_group
   ```
4. **短路匹配 (First-Match) 六层黄金顺序**：
   - [第 1 层] 核心宿主进程与私网广播保护：`pname(dnsmasq, ...) -> must_direct` 及 `dip(geoip:private) -> direct`
   - [第 2 层] 大流量下载与 P2P 绕行：`pname(aria2c, qbittorrent-nox) -> must_direct`
   - [第 3 层] 境外 QUIC 抑制与 Canary 阻断：
     `l4proto(udp) && dport(443) && !domain(geosite:cn) -> block`
     `domain('use-application-dns.net', 'mask.icloud.com', 'mask-h2.icloud.com') -> block`
   - [第 4 层] 重点海外服务专属分流：`domain(geosite:google, geosite:openai) -> proxy`
   - [第 5 层] 大陆大盘双向白名单直连：`domain(geosite:cn) -> direct` 及 `dip(geoip:cn) -> direct`
   - [第 6 层] 终态回落兜底：`fallback: proxy`
5. **DNS 响应投毒重查闭环**：
   在 `dns.routing.response` 中，首行必须为白名单放行，防止无限递归死锁：
   ```shell
   response {
       upstream(googledns) -> accept
       ip(geoip:private) && !qname(geosite:cn) -> googledns
       fallback: accept
   }
   ```

---

## 二、 常用匹配选择器速查 (Routing Selectors)

| 选择器 | 语法示例 | 说明 |
| :--- | :--- | :--- |
| **进程匹配** | `pname(dnsmasq, aria2c)` | 匹配软路由本机发起的进程名 |
| **目标 IP** | `dip(geoip:private, 223.5.5.5)` | 匹配目标 IP 或 GeoIP 集合 |
| **源 IP / MAC** | `sip(192.168.1.100)`, `mac('00:11:22:33:44:55')` | 匹配局域网特定设备 |
| **目标域名** | `domain(geosite:cn, 'example.com')` | 匹配域名或 Geosite 规则集 |
| **传输协议/端口** | `l4proto(udp) && dport(53, 443)` | 匹配四层协议 (tcp/udp) 与端口 |

---

## 三、 复杂网络拓扑模块化组装配方 (Recipes)

### 配方 A：标准主路由模式 (Main Gateway)
```shell
global {
    lan_interface: br-lan
    wan_interface: auto
    auto_config_kernel_parameter: true
    tcp_check_url: 'http://cp.cloudflare.com'
}

routing {
    pname(dnsmasq, odhcpd, netifd, uhttpd) && l4proto(udp) && dport(53) -> must_direct
    dip(224.0.0.0/3, 'ff00::/8') -> direct
    dip(geoip:private) -> direct
    domain('use-application-dns.net', 'mask.icloud.com', 'mask-h2.icloud.com') -> block
    domain(geosite:cn) -> direct
    dip(geoip:cn) -> direct
    fallback: proxy
}
```

### 配方 B：单网口旁路由模式 (Bypass Gateway)
```shell
global {
    lan_interface: br-lan
    wan_interface: auto
    auto_config_kernel_parameter: true
}

routing {
    pname(dnsmasq, odhcpd, netifd, uhttpd) && l4proto(udp) && dport(53) -> must_direct
    dip(192.168.1.1) -> direct # 放行主路由自身 IP
    dip(geoip:private) -> direct
    domain('use-application-dns.net', 'mask.icloud.com', 'mask-h2.icloud.com') -> block
    domain(geosite:cn) -> direct
    dip(geoip:cn) -> direct
    fallback: proxy
}
```
> **旁路由防火墙配套**：必须在 OpenWrt LAN 区域执行 `uci set firewall.@zone[LAN].masq='1'`（或运行 `setup_openwrt_network.sh --bypass`）消除非对称路由丢包。
