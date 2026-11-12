# OpenWrt / ImmortalWrt / iStoreOS 软路由代理配置 Skills

面向 OpenWrt、ImmortalWrt、iStoreOS 的 Agent Skills，用于 sing-box 与 dae 两种透明代理方案的配置生成、部署与排障。

更新记录见 [CHANGELOG.md](CHANGELOG.md)。

本包包含 2026-11-12 的本地审计修订，原报告逐项核验、修复和实际验证边界见 [审计复核报告](docs/audit-2026-11-12.md)。该修订没有重新完成真机验证。

## 包含的技能

| 技能 | 引擎 | 说明 |
| :--- | :--- | :--- |
| [`singbox-openwrt`](skills/singbox-openwrt/SKILL.md) | sing-box 1.13 / 1.14+（TUN，FakeIP / RealIP） | 对内核与固件版本要求较低，作为默认方案 |
| [`dae-openwrt`](skills/dae-openwrt/SKILL.md) | dae（eBPF） | 需要 Linux 5.15+ 与 BTF，适用于满足条件的固件 |

技能按 `skills/<技能名>/SKILL.md` 组织，符合常见 Agent Skills 分发约定（`npx skills add`、anthropics/skills）。

## 工作流

1. **环境探针**（`probe.sh -j`）：发行版（精准识别 OpenWrt、ImmortalWrt、iStoreOS）、包管理器（实际检测 opkg 或 apk）、内核与 BTF、内存与存储空间、冲突插件，输出机器可读 JSON。
2. **配置生成与积木拼装**（`auto_config.py`、`sub_parser.py`、`assets/mixins/`）：通用订阅清洗、自适应版本模板选择、Mixins 积木拼装、CDN 规则集镜像、生成后内置静态审计。
3. **Agent 自主原子部署**（标准 SSH 管道）：远端沙盒语法与依赖校验（`sing-box check` / `dae validate`）、保留快照备份、原子替换、平滑重启或无感热重载。
4. **最后一公里网络闭环**（`setup_openwrt_network.sh`）：LAN 区域动态定位并注入 `tun0` 放行、开启 forward=ACCEPT、MSS 钳制 (`mtu_fix=1`)、清理干扰三层 `hijack-dns` 的本机 53 DNAT 重定向、Dnsmasq `filter_aaaa=1` 过滤、内核 BBR 调优；支持 `--bypass` 自动开启旁路由动态伪装 (`masq=1`)。
5. **结构化自愈诊断**（`doctor.sh --json`、`diagnose_dns.sh --json`）：机器可读 JSON 诊断输出，包含状态码、问题特征与自愈执行命令。

## 参考文档

| 文档 | 内容 |
| :--- | :--- |
| [architecture-and-schema.md](skills/singbox-openwrt/references/architecture-and-schema.md) | sing-box 架构规范、OpenWrt 硬件防护基线、v1.13 vs v1.14 字段门控与兼容矩阵 |
| [dns-and-routing.md](skills/singbox-openwrt/references/dns-and-routing.md) | RealIP vs FakeIP 机制、DNS 防污染、Canary 域名阻断与多级解析防环 |
| [openwrt-pitfalls-and-troubleshooting.md](skills/singbox-openwrt/references/openwrt-pitfalls-and-troubleshooting.md) | OpenWrt 闪存寿命保护、防火墙 tun0 放行、常见症状与排障速查索引 |
| [modular-blocks.md](skills/singbox-openwrt/references/modular-blocks.md) | 模块化规则积木与主路由/旁路由/指定设备分流等复杂拓扑组装指南 |
| [dae-rules-and-syntax.md](skills/dae-openwrt/references/dae-rules-and-syntax.md) | dae 5 条语义与拓扑铁律、路由语法、网卡绑定约束与 DNS 重查白名单 |
| [troubleshooting.md](skills/dae-openwrt/references/troubleshooting.md) | dae 常见故障诊断排查手册与内核 eBPF 日志特征速查 |
| [warnings-and-limitations.md](docs/warnings-and-limitations.md) | 生产环境已知边界、架构限制、版本演进、避坑与安全免责警告 |
| [compatibility-matrix.json](docs/compatibility-matrix.json) | 机器可读的发行版/防火墙/包管理器兼容矩阵与 R0~R4 动作风险分级规范 |
| [BASELINE.md](docs/quality/BASELINE.md) | v1.0.0 质量基线、问题台账 ([KNOWN_ISSUES.md](docs/quality/KNOWN_ISSUES.md))、分层测试 ([TEST_BASELINE.md](docs/quality/TEST_BASELINE.md)) 与发布证据 ([RELEASE_EVIDENCE.md](docs/quality/RELEASE_EVIDENCE.md)) |

## 目录结构

```
.
├── skills/                   # 可分发给 Agent 的技能包（符合 SKILL.md 目录约定）
│   ├── singbox-openwrt/      # sing-box 技能
│   │   ├── SKILL.md
│   │   ├── assets/
│   │   │   ├── mixins/       # 模块化配置片段 (TUN入站/DNS/路由/实验性缓存/出站)
│   │   │   └── templates/    # 4 个基准模板（1.13/1.14 × FakeIP/RealIP）
│   │   ├── scripts/          # 生成 / 诊断 / 网络闭环接管脚本
│   │   └── references/       # 架构规范、DNS防环、避坑排障、模块化积木（一级深度）
│   └── dae-openwrt/          # dae 技能
│       ├── SKILL.md
│       ├── assets/templates/ # openwrt.dae 基准模板
│       ├── scripts/          # 探针 / 诊断 / 网络闭环接管脚本
│       └── references/       # 5条铁律与语法、故障排查手册（一级深度）
├── core/                     # 核心安全策略、Policy Engine、动作注册表与事务状态机（v1.0.0）
├── docker/                   # 本地 OpenWrt 自动化测试基座（Docker 容器 & Mock 仿真）
├── docs/                     # 真机验证报告
├── tests/                    # 回归测试（unittest，无第三方依赖）
├── run_tests.py              # 一键回归入口
├── HARDENING_REPORT.md       # 稳定性加固与边界异常测试审计报告
└── .github/workflows/ci.yml  # GitHub Actions
```

`templates/` 置于 `assets/templates/` 下，对应 Agent Skills 规范中 `assets/` 存放静态资源的约定；引用路径在各 SKILL.md 中显式给出。

## 安装

### DeepSeek Harness (DSH)

技能按 `<agentsHome>/skills/<技能名>/SKILL.md` 发现，因此指向仓库内的 `skills/` 子目录：

```powershell
# Windows（junction 方式，修改仓库内容后即时生效）
# 注意：把 <仓库路径> 换成你 clone 本仓库的实际位置，例如 D:\openwrt-proxy-skills
cmd /c rmdir "$env:USERPROFILE\.agents\skills"           # 仅移除链接本身，不影响目标目录
New-Item -ItemType Junction `
  -Path   "$env:USERPROFILE\.agents\skills" `
  -Target "<仓库路径>\skills"
```

`~/.agents` 同时是 DSH 的 agents home。如果其它工具（例如 Antigravity）也在使用该目录，请先确认。

### Claude Code 及其它支持 SKILL.md 的工具

将两个技能目录复制到技能根即可：

```bash
cp -r skills/singbox-openwrt skills/dae-openwrt ~/.claude/skills/
```

## 适用场景

- OpenWrt / ImmortalWrt / iStoreOS 上的透明代理（TUN 或 eBPF）配置
- 导入或更换节点（vless / hysteria2 / trojan / ss / vmess）与机场订阅
- 全屋断网的排查，例如局域网设备无法访问境外站点
- 从 PassWall / OpenClash / HomeProxy 迁移到 sing-box 或 dae
- dae 的规则编写、DNS 防环与热重载

## 设计约束

- 配置修改先写入 `/tmp`，远端 `check` / `validate` 通过后才替换生产配置；
- 部署前保留快照，进程异常时回滚；
- 缓存文件固定放在 `/tmp` 下，避免向闪存写入；
- TUN 模式需要在防火墙中放行 `tun0`；
- dae 需要内核 5.15+ 与 BTF，不满足时建议改用 sing-box。

## ⚠️ 使用须知与架构边界（用户必读）

为确保生产环境软路由高可用与网络稳定，请在部署前仔细阅读以下关键边界与安全提示（技术细则见 [docs/warnings-and-limitations.md](docs/warnings-and-limitations.md)）：

1. **GitHub 认证凭据与隐私隔离保证**：用户的 GitHub 访问凭据（Token / SSH Key）由操作系统底层（Windows 凭据管理器 / SSH Agent）加密隔离，Git 机制物理级禁止打包 `.git` 内部配置；个人真实节点与敏感文件受 `.gitignore` 保护，绝无泄露风险。
2. **sing-box 版本演进前瞻警告**：基准模板深度稳定覆盖 sing-box 1.13 与 1.14 架构；针对后续可能推出的重大版本（如 1.15+），**现有模板或将重新适配**，切勿盲目跨大版本替换二进制，升级前必须先在沙盒环境验证配置。
3. **Clash YAML 锚点降级解析边界**：纯 Python 正则降级解析器支持常规单行标量与缩进列表锚点，但面对部分机场深度复合的多重锚点合并（如 `<<: [*a, *b]`）等极端语法可能受限，软路由建议预装 `python3-pyyaml` 获取 100% 完整解析能力。
4. **daed (Web 面板) 与 原生 dae (CLI) 二选一铁律**：严禁同时使用 Web 面板管理和脚本外部覆写 `/etc/dae/config.dae`，面板 SQLite 托管与外部文本配置会发生竞争覆写，请二选一。
5. **弱硬件路由性能与闪存寿命保护**：百级订阅默认截断至前 15 个节点以防弱内存路由 OOM；低配设备加载 eBPF 建议配置 Swap 交换空间；全链路在 `/tmp` 内存虚拟盘缓冲以保护 SPI 闪存寿命。
6. **FakeIP 引导与 DNS 循环防环**：严禁将 `domain_resolver` 指向自身为 `fakeip` 的上游服务器；生产部署前务必使用 `check_config.py` 与 `check_dae_syntax.py` 执行静态门禁校验。
7. **旁路由与 IPv6 假死防护**：旁路由网关模式部署必须携带 `--bypass` 自动注入物理网卡 MASQUERADE 动态伪装；建议开启 Dnsmasq `filter_aaaa=1` 避免国内双栈访问转圈假死。

## 测试

```bash
# 1. 单元回归测试（纯标准库无依赖）
python run_tests.py

# 2. 本地 OpenWrt 自动化流水线测试（支持 Docker 容器或本地 Mock 仿真）
python docker/run_docker_tests.py

# 3. 工业级异常边界与可靠性压力测试矩阵（默认 DRY-RUN 安全模式，支持带快照安全演练）
python docker/stress_test_matrix.py
```

本地测试基座设计与用法详见 [docker/README.md](docker/README.md)。

测试覆盖：模板字段与引用完整性、节点解析、订阅清洗、生成器端到端与静态校验、两个检查脚本、文档链接、shell 语法与行尾规范。GitHub Actions 在推送与 PR 时对多个 Python 版本执行同一套测试。

真机验证记录（ARM64 软路由网关 / ImmortalWrt SNAPSHOT / sing-box 1.14.3）见 [docs/validation-report.md](docs/validation-report.md)。

## 致谢与第三方内容

第三方内容的版权说明见 [NOTICE.md](NOTICE.md)。

- sing-box：<https://github.com/SagerNet/sing-box>。`singbox-openwrt` 的模板骨架参考 [shpirt/singbox-config](https://github.com/shpirt/singbox-config) 修改而来。
- dae / daed：<https://github.com/daeuniverse/dae>。
- 规则集：<https://github.com/SagerNet/sing-geosite>、<https://github.com/SagerNet/sing-geoip>。

## 声明

- 本项目为个人维护的开源项目，与 OpenWrt、ImmortalWrt、iStoreOS、SagerNet、daeuniverse 等项目没有隶属或合作关系，也不代表上述项目的官方立场。
- 文档中的命令、参数与判断基于公开资料和测试环境整理，不同固件、内核与版本下可能不同，请以实际设备输出为准。
- 本项目不提供任何订阅、节点或代理服务，也不包含可用的服务器地址；模板中的节点与地址均为占位示例。

## 免责声明

本项目仅用于技术学习与合法的网络配置。请遵守所在地法律法规及所使用服务的条款。使用本项目造成的任何直接或间接损失，作者不承担责任。

## License

[MIT](LICENSE)
