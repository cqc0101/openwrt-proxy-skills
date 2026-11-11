# 真机验证报告 — ARM64 软路由网关 (ImmortalWrt SNAPSHOT)

- 验证日期：2026-11-08
- 设备：标准 ARM64 软路由硬件网关，ImmortalWrt SNAPSHOT r0-3e24625，aarch64
- 内核：6.18.44；内存 495MB；overlay 43.7M（可用 35.8M）；包管理器 **apk**（SNAPSHOT 主分支）
- 网络：br-lan=192.168.10.1（LAN），eth0=192.0.2.220（上行 DHCP，上游为 192.0.2.1）
- 授权范围：仅本从路由设备可读写；未触碰上游网关（192.0.2.1）与外部服务器。
- 设备最终状态：**已恢复基线**（sing-box 服务停用、分载恢复、防火墙还原、临时 hook 清除）。

## 一、验证矩阵（全部在真机实际执行）

| 组件 | 结果 | 备注 |
| :--- | :--- | :--- |
| `probe.sh` | ✅ 运行正常 | 发行版/架构/apk/BTF/冲突检测全部准确 |
| `diagnose_openwrt.sh` | ✅ 运行正常 | 内存单位 bug 见下文；出口检测准确 |
| `doctor.sh` | ✅ 运行正常 | 真实日志上无误报 |
| `check_dae_syntax.py` | ✅ | 模板通过 |
| `auto_config.py`（真实节点 ×5） | ✅ | 生成后自审计零错误 |
| `deploy_singbox.sh`（完整流水线） | ✅ | 见下：4 轮迭代后全绿 |
| `setup_openwrt_network.sh` | ✅ | fw4 识别、zone 按名定位、tun0 注入、reload 全部正常 |
| Clash API 9090 | ✅ | 版本接口与 proxies 接口正常 |
| 出海落地 | ✅ | 出口 IP = 境外 VPS 落地节点（198.51.100.1） |
| `deploy_dae.sh` 拒绝路径 | ✅ | 无 BTF → 警告 + 干净中止（exit 1，零副作用） |
| 崩溃自动回滚 | ✅ | 第 1 轮部署失败时真实触发：快照还原、网络未中断 |

## 二、真机发现并已修复的问题（本仓库已改）

| # | 问题 | 根因 | 修复 |
| :--- | :--- | :--- | :--- |
| 1 | **内存数值放大 1000 倍**（495388MB） | 该 BusyBox 的 `free` 不支持 `-m`，静默忽略后仍输出 KB | probe/diagnose 改读 `/proc/meminfo`（kb→MB） |
| 2 | **scp 上传直接失败**（`sftp-server: not found`） | 精简固件 dropbear 未装 openssh-sftp-server | 部署脚本改 ssh+stdin（`cat > /tmp/...`），sh/ps1 同步 |
| 3 | **部署被误判 Crash 并回滚** | apk 安装后 sing-box 服务默认 `enabled=0`，`/etc/init.d/sing-box restart` 静默无效 | 部署脚本自动 `uci set sing-box.main.enabled='1'`（workdir 一并修正），健康检查文案区分"未启用 vs 崩溃" |
| 4 | **规则集下载 detour 指向 direct 导致启动即崩**（`detour to an empty direct outbound makes no sense`） | 直连下载是默认行为，显式 `download_detour: "direct"` / `http_client.detour: "direct"` 触发 sing-box 启动期保护 | 4 个模板删除该写法；`check_config` 新增致命模式检测；测试与文档同步（troubleshooting E6） |
| 5 | **国内直连被 TUN 自捕获（路由器自身 baidu 000→RST）** | 该内核缺 `nfnetlink_queue`/`nft_queue`（启动日志 `nfqueue start failed`），`auto_detect_interface` 自保失效 | `auto_config` 新增 `--wan-iface`（生成 `route.default_interface`）；probe 报告"默认路由接口"；部署脚本双探针（国内+出海）区分该故障并给出修复指引（troubleshooting E8） |
| 6 | **部署脚本无法指定密钥**（仅默认密钥路径） | BatchMode 场景需要非默认身份文件 | sh/ps1 均新增第 5 参数 SSH_KEY / `-KeyPath` |

每项修复都有回归测试守护（当前 102 项全绿；新增：detour-direct 致命模式、wan-iface 行为、服务启用断言、共享脚本一致性扩展到 6 文件）。

## 三、性能数据（带混杂因素，仅参考）

| 路径 | 结果 | 说明 |
| :--- | :--- | :--- |
| 50MB 下载经从路由（WiFi → TUN → 上游代理） | 2.59 MB/s | WiFi 接入 + 双层代理 |
| 50MB 下载以太网直连上游网关 | 5.73 MB/s | 以太网 + 单层代理 |

对比不公平（WiFi vs 以太网），**不作为代理性能结论**；仅证明整链路吞吐可用。设备资源占用：sing-box VmRSS 49MB（GOMEMLIMIT=220MiB 内），负载 0.18。

## 四、已知限制与未闭环项（如实记录）

1. **nfqueue 模块缺失**：本设备内核无 `nfnetlink_queue`/`nft_queue`，`auto_redirect` 的 pre-match 被禁用（sing-box 日志明确告警，降级运行不崩）。此类内核必须走 `--wan-iface` 路径（已产品化）。
2. **双层透明代理拓扑**：从路由上游存在主网关透明代理。终端设备经从路由 WiFi 的部分链路建议结合具体局域网环境独立复核；出海路径（经境外节点）在基线期与部署期均正常。
3. **qq.com 对 curl UA 返回 501** 属站点反爬行为，非网络故障。
4. 部署脚本重启时 `ubus call service delete` 报 Not found 为无害噪音（首次注册前删除），暂未抑制。
5. `sing-box-tiny`（1.14.3，39MiB）保留安装在设备上（服务已停用、enabled=0），供后续验证直接使用；完整版 `sing-box` 62MiB **无法安装**在 43.7M overlay 的小闪存设备上——选择 tiny 变体是此类设备的必要路径（已记录进本报告）。

## 五、设备恢复清单（已执行）

- `/etc/init.d/sing-box stop` + `uci set sing-box.main.enabled=0`
- 恢复包默认配置 `/etc/sing-box/config.json`（从首轮部署快照）
- 恢复 `flow_offloading=1` / `flow_offloading_hw=1`
- 移除 tun0 的 lan zone 条目与 `/etc/hotplug.d/iface/99-singbox`
- 复核：路由器自身 baidu 200 / qq 501(UA) / CF 204 / google 200；无代理进程残留
- 本地 `.deploy_key/`（SSH 密钥，gitignored）与设备上 authorized_keys 保留，便于后续验证；`.tmp/` 中的含凭据配置已删除

## 六、结论

- **可用性**：探针/生成/部署/防火墙/回滚/dae 拒绝 全链路在真机跑通；部署流水线经 4 轮迭代后"一次成功"。
- **代码完善度**：真机暴露 6 个真实缺陷（含 2 个启动即崩级），已全部修复并有 102 项回归测试守护——真机验证的价值被充分兑现。
- **剩余风险**：双层代理拓扑下的局域网客户端国内直连需要独立环境复核（见四-2）。
