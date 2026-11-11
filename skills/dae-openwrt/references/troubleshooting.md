# dae 排障手册、硬件依赖与新老版本兼容速查

> 集中归纳 dae eBPF 运行时的底层硬件约束、新旧版本差异、常见故障病因与针对性解法。

---

## 一、 硬件与内核门禁 (新老软路由分级矩阵)

dae 深度依赖 Linux 内核 eBPF TC 特性，不同代际软路由的适配策略如下：
1. **老款软路由（Linux < 5.15，如 OpenWrt 18.06 / 19.07 / 21.02 / 22.03 的 4.14、5.4、5.10 内核）**：不支持 eBPF CO-RE，`probe.sh -j` 会自动输出 `"dae_capable": 0, "recommended_engine": "sing-box"`，由 `singbox-openwrt`（兼容 `fw3/iptables` 与全版本内核）无损接管。
2. **中期软路由（Linux 5.15 ~ 5.16 + BTF，如 OpenWrt/ImmortalWrt 23.05）**：支持软件源内的老版本 `dae`（如 `v1.0.0-r1`），或切换 `singbox-openwrt`。
3. **新款软路由（Linux >= 5.17 + BTF，如 ImmortalWrt/OpenWrt 24.10 / 25+ 的 6.1、6.6+ 内核）**：完美支持最新原生 `dae v2.1.1+`。

---

## 二、 老版本 dae (`<= v1.0.0`) 与新版本 dae (`v2.1.1+`) 差异与自动兼容

| 差异维度 | 老版本 `dae` (`v0.3` ~ `v1.0.0-r1`) | 新版本 `dae` (`v1.1+` / `v2.1.1+`) | 技能自适应兼容方案 |
| :--- | :--- | :--- | :--- |
| **新增配置字段** | 不识别 `bpf_conn_state_map_size`、`auto_sniff_punt`、`bootstrap_resolver`、`optimistic_cache`、`optimistic_cache_ttl`（写入会报 `unexpected field`） | 原生支持上述 5 个性能与防断流字段 | `sub_to_dae.py --full` 支持 `--router <IP>` 自动探测远端版本（或显式传 `--dae-version legacy`），对老版本自动剥离上述 5 个字段 |
| **CLI 校验命令** | 支持 `dae validate -c <file>`，极早期版本支持 `dae validate <file>` | **强制要求 `-c`**：`dae validate -c <file>`（漏传 `-c` 直接报错退出） | 统一使用 `dae validate -c /tmp/config.dae.test \|\| dae validate /tmp/config.dae.test` |
| **DNS `qname()` 词法** | 宽松解析 | `addQName` 强制要求带前缀（如 `geosite:cn`、`suffix:example.com`），裸单引号域名会崩溃 | `qname()` 仅保留 `qname(geosite:cn)`，域名黑名单移入 `routing {}` 的 `domain(suffix: ...)` |

---

## 三、 核心生产事故与排障矩阵

| 故障现象 | 根本病因 | 针对性排查与自愈指令 |
| :--- | :--- | :--- |
| **启动后全屋断网** | `dnsmasq` 53 端口查询被递归拦截死锁 | 检查 `routing` 首行是否有 `pname(dnsmasq, ...) && l4proto(udp) && dport(53) -> must_direct` |
| **国内直连出海均超时** | OpenWrt 开启了 Flow Offloading (软/硬件流量分载) | 运行 `uci set firewall.@defaults[0].flow_offloading='0' && /etc/init.d/firewall reload` |
| **老版本 dae 校验报 unexpected field** | 路由器安装的 `dae <= v1.0.0` 不支持 v2.x 新增字段 | 运行 `python scripts/sub_to_dae.py "<订阅>" --full --dae-version legacy -o /tmp/config.dae` 重新生成 |
| **旁路由客户端断网/假死** | 非对称路由导致客户端 TCP RST | 运行 `sh setup_openwrt_network.sh --bypass` 开启 LAN 伪装 |
| **内存溢出 (OOM) 杀掉进程** | 弱小路由器加载了全量巨型 GeoIP/Geosite | 生成时传入 `--ram-mb 256` 自动调小 `bpf_conn_state_map_size` 并精简规则集 |

---

## 四、 支持的代理协议 URI 格式

dae 原生支持的单节点链接格式（均需使用单引号包裹）：
* **VLESS Reality**: `'vless://uuid@host:port?security=reality&sni=xxx&pbk=xxx&sid=xxx&type=tcp&flow=xtls-rprx-vision#Tag'`
* **Hysteria 2**: `'hysteria2://password@host:port?sni=xxx&insecure=0#Tag'`
* **Trojan**: `'trojan://password@host:port?sni=xxx#Tag'`
* **Shadowsocks**: `'ss://base64(method:password)@host:port#Tag'`

> **注意**：dae 仅支持原生标准协议 URI，不支持带有复杂客户端扩展私有参数的非常规链接；订阅解析请统一使用 `python scripts/sub_to_dae.py "<URL>" --max 15`。

---

## 五、 新一代 `apk` 固件与无网环境 SSH 流式管道交付 (SSH Stream Pipe)

当 ImmortalWrt / OpenWrt 24/25+ 全面切换至 `apk` 包管理器且官方源暂未收录最新原生 `dae`（或软路由处于初始未联网状态，无法在线 `apk add` / 拉取 GeoData）时，采用宿主机 **SSH Stream Pipe（流式管道直灌）** 彻底破除鸡生蛋死锁：

```bash
# 1. 根据 probe.sh -j 探测到的架构 (如 x86_64 / aarch64)，从宿主机流式灌入 dae 二进制与 GeoData
ssh root@192.168.1.1 "mkdir -p /usr/bin /usr/share/dae /etc/dae && cat > /usr/bin/dae && chmod 755 /usr/bin/dae" < ./dae-linux-${ARCH}
ssh root@192.168.1.1 "cat > /usr/share/dae/geoip.dat && chmod 644 /usr/share/dae/geoip.dat" < ./geoip.dat
ssh root@192.168.1.1 "cat > /usr/share/dae/geosite.dat && chmod 644 /usr/share/dae/geosite.dat" < ./geosite.dat

# 2. 沙盒校验（注意：dae v2.1.1+ 必须携带 -c 参数）
ssh root@192.168.1.1 "dae validate -c /etc/dae/config.dae || dae validate /etc/dae/config.dae"
```
