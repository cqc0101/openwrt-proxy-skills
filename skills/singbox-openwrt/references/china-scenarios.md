# 中国家庭网络场景库 (China Scenarios)

> 英文文档没有、只在中文软路由圈沉淀的实战场景。每条配方都以「配置 → 验证」闭环给出。
> 涉及 UCI 修改的一律先备份：`cp -r /etc/config /etc/config.bak.$(date +%s)`。

---

## 1. 机场订阅接入

### 订阅形态识别
| 形态 | 特征 | 处理 |
| :--- | :--- | :--- |
| Base64 包裹 | 一大串字母数字，可能每 76 字符换行 | `sub_parser` 自动识别解码 |
| Clash YAML | 含 `proxies:` | 自动解析 `proxies` 列表转 outbound |
| 多行 URI | `vless://` `trojan://` 等逐行 | 直接逐行解析 |

### 常见坑
- **“剩余流量/到期时间/官网公告”伪节点**：`filter_nodes` 内置黑名单自动剔除；若误删可用 `--include` 精确圈选。
- **订阅拉取失败**：先在电脑上 `curl -I <订阅链接>` 验证链接本身可用；机场常要求特定 User-Agent（脚本已内置）。
- **上百节点冲垮 256MB 路由**：一律 `--max-nodes 15`（默认），别贪多。
- **节点测速全红 ≠ 节点全坏**：可能是 `tcp_check_url` 被运营商干扰；模板用 Cloudflare 204，可换成 `http://www.gstatic.com/generate_204`。

## 2. 光猫桥接 + PPPoE 拨号

- 路由器 WAN 走 PPPoE 时，dae 的 `wan_interface` 应设为 **PPP 虚接口**（如 `pppoe-wan`）或 `auto`，不是物理网口。
- PPPoE 半夜踢线重拨是常态 → 部署脚本已内置 `/etc/hotplug.d/iface/99-*` 自愈钩子，装完后 `ls /etc/hotplug.d/iface/` 确认存在。
- 光猫桥接失败（WAN 拿不到地址）：先进光猫后台确认连接模式是 Bridge；超级密码找运营商/网上对应型号教程，**不要重置光猫**。

## 3. 旁路由（透明网关）模式

主路由不跑代理，把局域网设备的网关与 DNS 指向旁路由：

1. 旁路由配置与主路由模式相同（TUN/dae 均可），但 `lan_interface` 绑旁路由 LAN 口。
2. 主路由 DHCP 下发：网关=旁路由 IP，DNS=旁路由 IP。
3. 不想动全局时，只给需要出海的设备手配静态网关。

**两个必踩的坑：**

- **IPv6 泄漏**：旁路由没接管 IPv6 时，设备可能拿主路由的 IPv6 直连出海（绕过代理）。要么主路由 LAN 侧关 RA/DHCPv6，要么设备侧禁 IPv6。验证：设备上 `ip -6 route` 应只有链路本地，或 `curl -6 ip.sb` 不通。
- **改错网关 = 全网断**：改主路由 DHCP 前先确认旁路由代理已工作（旁路由上 curl 204 通过），并保留原配置可回滚。

## 4. 运营商 IPv6 与代理共存

- 国内 App（微信/淘宝）常见 IPv6 优先导致转圈 → 模板默认 `strategy: ipv4_only` + TUN 不给 IPv6 地址，已规避。
- **HTTPDNS 例外**：微信等 App 走 HTTPDNS 拿 IP，DNS 模块管不到；但只要 TUN 没有 IPv6 地址，App 就只会走 IPv4（内核立刻报不可达，Happy Eyeballs 回退）。
- 需要真 IPv6 出海的用户：另行配置 IPv6 出口，**不要**在半 v4 半 v6 的状态下排查（症状错乱）。

## 5. Clash API 面板（零安装可视化管理）

- 模板默认 `0.0.0.0:9090`（无 secret），局域网浏览器打开：
  - https://yacd.haishan.me
  - https://metacubex.github.io/metacubexd/
- Host 填路由器 IP、Port 9090、Secret 留空。
- 面板能做：秒级测速、策略组点选切换、流量与连接跟踪。
- 打不开时先 `curl http://路由器IP:9090/version` 验证端口，再查防火墙。

## 6. 多拨 / 多 WAN 与代理叠加的坑

- 多拨后 sing-box 出口源 IP 会变 → `auto_detect_interface: true` 可跟随默认路由，但**节点可能因多 IP 频繁切换被判异常**；优先给代理固定一条线路（mwan3 规则按目的分流）。
- 简化原则：代理流量集中走一条 WAN，PT/下载走另一条，别让代理流量在多线路上漂。

## 7. 常见 App 专项

| App/现象 | 处置 |
| :--- | :--- |
| 微信打开慢/转圈 | 确认 TUN 无 IPv6 地址；微信 HTTPDNS 会拿 v6 → 无 v6 路由即回退 v4 |
| Apple 服务/商店 | 用 `geosite-apple` + `geosite-apple@cn` 分别分流（国内用阿里 DNS，海外走代理） |
| 国服游戏 | 直连规则（`geosite-cn` + `geoip-cn` 已覆盖）；登录异常先排除 UDP 被 block |
| 网飞/油管 | 模板已内置 `geosite-google/youtube` 与 AI 分流，Netflix 加 `geosite-netflix` |

## 8. 出问题时的标准动作（一次成功的关键）

1. 跑 `sh scripts/diagnose_openwrt.sh`（或 Windows 远程版）拿全景报告；
2. 对照 [troubleshooting-index.md](./troubleshooting-index.md) 按现象定位；
3. 改配置走 `deploy_*.sh`（沙盒校验 + 快照 + 自动回滚），**绝不手改 /etc**；
4. 改完立刻用「验证」列的命令确认，而不是“感觉好了”。

## 9. 多级代理叠加（真机踩坑记录）

在"主路由已跑透明代理"的网络上，旁路由再叠一层 TUN 时注意：

- **只保留一层做透明代理**：首层（主路由）优先。叠加会导致排障时无法判断哪一层在丢包。
- **缺 nfqueue 模块的内核**：`auto_detect_interface` 自保失效、国内直连被 TUN 自捕获（出海正常、国内 RST）——用 `--wan-iface <WAN接口>` 生成配置。
- **流量分载必须关闭**（软/硬 offload 都会绕过 TUN 钩子）：`uci set firewall.@defaults[0].flow_offloading='0'`。
- **先做基线对照**：部署前先测"国内直连 + 出海"两个探针并记录，部署后对比；基线就异常的问题与本机配置无关。
- 客户端侧部分国内站点对 curl UA 返回 501/reset 属反爬，浏览器验证为准。
