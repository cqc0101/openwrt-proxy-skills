# 出海排障索引 (Troubleshooting Index)

> 用法：先按「现象」定位行，再按「先查→再修」顺序执行。每行给出可复制的排查命令与验证标准。
> 日志样例是常见形态，随版本可能变化；**以路由器上的真实日志为准，本表只负责指方向**。
> 铁律：诊断结论必须有命令输出支撑，禁止凭感觉下结论；改配置前先快照（`deploy_*.sh` 自带）。

---

## A. 全屋断网 / 局域网设备上不了网

| # | 现象 | 先查（命令） | 常见病因 → 修复 | 验证 |
| :--- | :--- | :--- | :--- | :--- |
| A1 | 刚开 TUN，全网设备断网 | `ip link show tun0`、`nft list ruleset` | tun0 未加入 lan zone → fw4 DROP 转发。跑 `setup_openwrt_firewall.sh` | 手机访问国内网站恢复 |
| A2 | 路由器能上网，设备不能 | `sysctl net.ipv4.ip_forward` | ip_forward=0 → `sysctl -w net.ipv4.ip_forward=1` | 返回 1 |
| A3 | 随机掉线、PPPoE 重拨后失联 | `logread | grep -i pppoe` | 重拨后内核路由表未恢复 → 检查 `/etc/hotplug.d/iface/99-singbox` 是否存在 | 触发重拨后代理自动恢复 |
| A4 | 改完配置立刻断网 | `ssh` 能否连上 | 配置错误且已覆盖生产 → 用 `deploy_*.sh` 的快照 `.bak.<时间戳>` 回滚 | 网络恢复 |
| A5 | 开机后必断一次 | `logread | grep -i "out of memory"` | 内存不足 OOM 杀进程 → 小内存设备用轻量模板 + GOMEMLIMIT（部署脚本自动注入） | 重启不再 OOM |

## B. 能上国内，不能出海（最典型）

| # | 现象 | 先查（命令） | 常见病因 → 修复 | 验证 |
| :--- | :--- | :--- | :--- | :--- |
| B1 | Google/YouTube 全挂 | `curl -s -o /dev/null -w "%{http_code}" http://cp.cloudflare.com/generate_204`（在路由器上） | 节点失效/密码错/端口被封 → Clash 面板换节点逐个测 | 返回 204 |
| B2 | 首次启动无法出海 | `logread | grep -i "rule-set\|rule_set"` | 规则集从 GitHub 下载失败（国内直连冷启动死锁）→ 重新生成配置加 `--mirror jsdelivr` | 日志无 rule-set 报错 |
| B3 | 网页能开但视频/下载慢 | `logread | grep -i quic` | 运营商 UDP QoS → 模板已内置 `udp 443 block`，确认该规则在分流规则里 | 视频缓冲正常 |
| B4 | 部分网站 502/证书错误 | `date` | 路由器时钟不对（断电后 RTC 失效）→ `ntpd -q -p ntp.aliyun.com` | 时间与手机一致 |
| B5 | 手机能出海电脑不能（或反之） | `ip route show table all \| grep tun0` | 设备绕过了 TUN（如手动设了 DNS/网关）→ 检查设备网关与 DNS 指向路由器 | 设备走代理 |
| B6 | IPv6 网站打不开 | `ip -6 route` | IPv6 无路由却发了 AAAA → 模板 IPv4-only；确认 TUN 无 IPv6 地址 | 只有 v4 路由 |

## C. DNS 类

| # | 现象 | 先查（命令） | 常见病因 → 修复 | 验证 |
| :--- | :--- | :--- | :--- | :--- |
| C1 | 解析很慢（几秒才出页面） | `dig baidu.com @127.0.0.1` 计时 | DNS 走了远端起解析 / 上游超时 → 国内域名确认走 `alidns` 规则 | 本地解析 <50ms |
| C2 | `.lan` / NAS 主机名失效 | `nslookup nas.lan 127.0.0.1` | FakeIP 劫持了局域网域名 → 确认模板 `.lan/.local/PTR` 规则送 `local-dns` | 解析出内网 IP |
| C3 | 出海域名解析到假 IP | `nslookup google.com 127.0.0.1` | RealIP 模式下走了国内 DNS 被投毒 → 海外域名规则路由到 `google-dns`（远程 DoH） | 返回真实 IP |
| C4 | 日志刷 DNS 回环/超时 | `logread | grep -i "loop\|recursion"` | 路由器自身 DNS 组件没被 `must_direct` 放行（dae）或 DNS 规则死循环 → 按模板首层规则检查 | 日志清净 |

## D. 性能与硬件保护

| # | 现象 | 先查（命令） | 常见病因 → 修复 | 验证 |
| :--- | :--- | :--- | :--- | :--- |
| D1 | CPU 常 100% | `top` / `mpstat` | 规则集过大（数万条全局 !cn）→ 用轻量模板靠 `final: proxy` 兜底 | CPU 降下来 |
| D2 | 内存被吃光 | `free` | 节点过多 / 规则集过大 → `--max-nodes 15` + 轻量规则集 | 内存余量稳定 |
| D3 | 配置改不了 / 只读 | `mount \| grep overlay`、`df -h /overlay` | 闪存写穿或 overlay 满 → 停止向 /etc 高频写，cache 一律 /tmp | 可写 |
| D4 | 启动时卡住很久 | `logread` 首屏 | 启动等待网络 + 规则集下载重试 → `disable_waiting_network` 类选项或 CDN 镜像 | 启动变快 |
| D5 | 温度报警 | `cat /sys/class/thermal/thermal_zone*/temp` | 高温降频 → 检查散热/负载，避免满载 | 温度回落 |

## E. 部署与配置类

| # | 现象 | 先查（命令） | 常见病因 → 修复 | 验证 |
| :--- | :--- | :--- | :--- | :--- |
| E1 | 部署被拦 | `deploy_*.sh` 输出 | 远端 `check/validate` 失败 → 沙盒已自动清理，按报错改配置重试 | 重新部署通过 |
| E2 | 提示字段废弃 | 部署脚本版本门控告警 | 1.13/1.14 字段混用 → 按 `compat-matrix.md` 只留一套 | 无告警 |
| E3 | `network: ws` 之类报错 | 部署失败日志 | 节点解析器旧 bug（已修复）→ 用当前仓库的 `parse_node.py` 重新生成 | 生成配置过 check |
| E4 | Clash 面板打不开 | `curl http://路由器IP:9090` | 面板没开 / 被防火墙挡 → 确认模板 `0.0.0.0:9090` 且放行端口 | 面板可访问 |
| E5 | 改了配置没生效 | `pidof sing-box` 之后看进程启动时间 | 改了 `/etc` 下的旧文件而非实际加载路径 → 走 deploy 脚本，勿手改 | 生效 |
| E6 | 启动即崩，日志 `detour to an empty direct outbound makes no sense` | `sing-box run -c <配置>` 前台复现 | 规则集/HTTP client 的下载 detour 指向了 `direct`（`download_detour: "direct"` 或 `http_client.detour: "direct"`）→ **删除 detour 字段**，直连下载是默认行为 | 前台启动无 FATAL |
| E7 | check 通过但部署后进程不在（被误报 Crash） | `uci get sing-box.main.enabled` | apk/opkg 安装后服务默认 `enabled=0`，`/etc/init.d/sing-box restart` 静默无效 → 部署脚本已自动启用；手改时记得 `uci set sing-box.main.enabled='1' && uci commit sing-box` | 返回 1 且进程在 |
| E8 | 出海正常、国内直连全挂（baidu 000/Connection reset） | 路由器上双探针：`curl -I baidu.com` 与 `curl -I cp.cloudflare.com/generate_204` | 内核缺 `nfnetlink_queue`/`nft_queue` 模块（日志见 `nfqueue start failed`）时，`auto_detect_interface` 的自保失效，直连流量被 TUN 自捕获 → **重新生成配置并追加 `--wan-iface <WAN接口>`**（或手工设 `route.default_interface`）；probe 报告里的“默认路由接口”即该值 | 双探针均 2xx |

## F. dae 专属

| # | 现象 | 先查（命令） | 常见病因 → 修复 | 验证 |
| :--- | :--- | :--- | :--- | :--- |
| F1 | 起不来，日志 eBPF/BTF | `uname -r`、`ls /sys/kernel/btf/vmlinux` | 内核 <5.15 或缺 BTF → 探针会拦截；改装 vmlinux-btf 或改用 sing-box | 探针 PASS |
| F2 | 代理完全失效 | `uci get firewall.@defaults[0].flow_offloading` | 流量分载让报文绕过 eBPF → 部署脚本会自动关闭，确认是 0 | 代理恢复 |
| F3 | DNS 死循环断网 | `logread | grep dae` | dnsmasq 等 53 流量未放行 → 模板首层 `pname(...) && l4proto(udp) && dport(53) -> must_direct` | 断网不再复现 |
| F4 | 局域网流量没被代理 | `logread | grep -i "lan_interface"` | `lan_interface` 没写或写错（PPPoE 场景是 `pppoe-wan` 而非物理口）→ 按实际网卡名修 | 设备出海 |

## G. 环境与固件

| # | 现象 | 先查（命令） | 常见病因 → 修复 | 验证 |
| :--- | :--- | :--- | :--- | :--- |
| G1 | 装包报 kernel 依赖 | `opkg install <kmod>` 输出 | kmod 与内核 ABI 不匹配 → 只用同分支源，或换固件（见 compat-matrix） | 安装成功 |
| G2 | opkg/apk 命令不存在 | `command -v opkg apk` | 24.10 及更早只有 opkg；apk 是 main 系列 → 用对的包管理器 | 命令可用 |
| G3 | 升级后代理失效 | `sing-box version` | 固件升级连带换了 sing-box 版本 → 重新探测版本并按门控生成配置 | 恢复 |
