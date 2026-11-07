# OpenWrt / ImmortalWrt 科学上网深度防坑指南 (sing-box 篇)

在软路由与 NAS 网关系统（OpenWrt 22.03 / 23.05 / 24.10+、ImmortalWrt、iStoreOS）部署 sing-box 客户端透明代理时，因路由器充当全屋唯一物理网关并采用特殊的防火墙和存储介质，必须严防以下特异性坑点：

---

## 避坑 1：OpenWrt fw4 (nftables) 阻断 tun0 转发（局域网无法上网）

### 表现现象
路由器自身在 SSH 终端下 `curl -I https://www.google.com` 正常连通，且 `pidof sing-box` 正常存活；但连接在软路由 LAN 口或 Wi-Fi 下的电脑、手机完全无法上网（甚至连国内网站和路由器后台都打不开）。

### 根本原因
自 OpenWrt 22.03 起，系统防火墙全面升级为 **fw4 (基于 nftables)**。fw4 默认启用严格的白名单区域隔离机制：**任何未在 `/etc/config/firewall` 的 `zone` 中声明的未知网卡（包括 sing-box 动态拉起的虚拟网卡 `tun0`），其与 LAN 物理网口之间的转发数据包（Forward Chain）会被直接丢弃（DROP）**。

### 彻底根治方案
一键将 `tun0` 纳入 LAN 区域设备放行列表（**注意：不要写死 `@zone[0]`**，zone 顺序不保证 lan 在第一位，必须按 name 定位）：
```bash
LAN_IDX=$(i=0; while uci get firewall.@zone[$i].name >/dev/null 2>&1; do [ "$(uci get firewall.@zone[$i].name)" = "lan" ] && { echo $i; break; }; i=$((i+1)); done)
[ -n "$LAN_IDX" ] && uci add_list firewall.@zone[$LAN_IDX].device='tun0' && uci commit firewall && /etc/init.d/firewall reload
```
或直接调用技能自带脚本（推荐，脚本已内置上述 zone 定位逻辑）：
```bash
bash scripts/setup_openwrt_firewall.sh <路由器IP>
```

---

## 避坑 2：路由器闪存（Flash）磨损与 OOM 崩溃

### 表现现象
路由器稳定运行一段时间后突然提示只读文件系统（Read-only file system），无法保存任何配置修改，重启后丢失数据甚至变砖。

### 根本原因
大量家用嵌入式路由器（如 MT7981、MT7621、公版 OpenWrt 路由器）内置板载闪存仅有 128MB 或 256MB SPI-NAND / SPI-NOR，擦写寿命通常仅数万次。
若在 sing-box 的 `experimental.cache_file` 中省略 `path`（默认写入当前运行目录如 `/etc/sing-box/cache.db`），频繁发生的 DNS FakeIP 映射、连接追踪记录和远程规则集自动持久化会高频读写闪存颗粒，导致芯片过早出现物理坏块！

### 规范做法
1. **强制指向内存临时区**：
   ```json
   "experimental": {
     "cache_file": {
       "enabled": true,
       "path": "/tmp/sing-box-cache.db",
       "store_fakeip": true
     }
   }
   ```
   OpenWrt 的 `/tmp` 挂载在 RAM（tmpfs）虚拟内存中，零闪存擦写，彻底杜绝硬件损耗。
2. **小内存设备防护**：
   对于 512MB 及以下内存的路由器，为防止启动阶段并发下载解析大规则集时触发 Linux OOM 杀进程，建议在外置 U 盘或 TF 卡上配置 512MB 虚拟交换分区（Swap）。

---

## 避坑 3：路由自环路与规则集下载死锁

### 表现现象
sing-box 启动后软路由 CPU 飙升至 100%，日志中频繁刷出 `download rule-set error: context deadline exceeded`，全屋网络瞬间瘫痪。

### 根本原因
1. **路由环路**：TUN 接管系统默认路由后，如果 sing-box 的外部连接没有绑定真实的物理出口网卡，其发往远端 VPS 节点的流量会被再次捕获送入 `tun0`，形成无限循环。
2. **规则集下载死锁**：sing-box 启动时需从 GitHub 下载 `.srs` 远程规则集。如果此时尚未指定出站引导域名解析器，sing-box 无法解析 `raw.githubusercontent.com`；而因为规则集拉取失败，sing-box 的代理和 DNS 服务又无法正常启动，形成死锁。

### 规范做法
在 `route` 模块中**必须显式配置**：
```json
"route": {
  "auto_detect_interface": true,
  "default_domain_resolver": "alidns"
}
```
* `auto_detect_interface: true`：使出站流量自动绑定物理 WAN 接口，杜绝环路。
* `default_domain_resolver`：指定国内直连 DNS（如阿里公共 DNS）解析节点域名与规则集下载域名。

---

## 避坑 4：IPv6 导致国内 App 转圈与打不开

### 表现现象
手机连接 Wi-Fi 后，微信/淘宝/京东等国内 App 打开首页卡顿数秒、图片刷新缓慢，或某些国服手游无法登录。

### 根本原因
如果代理环境配置了双栈 IPv6，部分国内 App 会优先使用 IPv6 连接。当运营商 IPv6 路由绕行或代理对 IPv6 UDP 支持不佳时，会造成严重丢包与重传。

### 规范做法
除非用户明确确认所在宽带 IPv6 优质且必须使用，否则在 OpenWrt 客户端配置中遵循 **IPv4 优先/纯净原则**：
* DNS 模块：`"strategy": "ipv4_only"`
* TUN 入站：仅配置 IPv4 地址（`"address": "172.19.0.1/30"`），不给 TUN 配置 IPv6 地址。
