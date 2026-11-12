# OpenWrt / ImmortalWrt / iStoreOS 软路由代理配置 Skills

面向 OpenWrt、ImmortalWrt、iStoreOS 的 Agent Skills，用于 sing-box 与 dae 两种透明代理方案的配置生成、部署与排障。

更新记录见 [CHANGELOG.md](CHANGELOG.md)。

本包包含 2026-11-12 的审计修订，原报告逐项核验、修复和实际验证边界见 [审计复核报告](docs/audit-2026-11-12.md)。后续已在 NanoPi R2S 上验证网络恢复、重启恢复、原生校验与部分运行路径；TUN、物理 LAN 透明转发和完整 IPv6 尚未完成，详见 [硬件审计报告](reports/hardware/FINAL-REPORT.md)。

## 包含的技能

| 技能 | 引擎 | 说明 |
| :--- | :--- | :--- |
| [`singbox-openwrt`](skills/singbox-openwrt/SKILL.md) | sing-box 1.13 / 1.14+（TUN，FakeIP / RealIP） | 对内核与固件版本要求较低，需要 TUN 支持 |
| [`dae-openwrt`](skills/dae-openwrt/SKILL.md) | dae（eBPF） | 需要 Linux 5.15+ 与 BTF，适用于满足条件的固件 |

技能按 `skills/<技能名>/SKILL.md` 组织，符合常见 Agent Skills 分发约定（`npx skills add`、anthropics/skills）。

## 工作流

1. 用 `probe.sh -j` 检查发行版、包管理器、内核、内存和冲突服务。
2. 用 `auto_config.py` 或 `sub_to_dae.py` 解析订阅并生成配置，需要时组合 `assets/mixins/` 中的片段。
3. 静态检查后，在目标路由器运行 `sing-box check` 或 `dae validate`。保留原配置再替换、重载服务。
4. 用 `setup_openwrt_network.sh` 配置转发、防火墙和 DNS。脚本保留恢复快照；确认实际流量正常后再执行 `--confirm`。旁路由使用 `--bypass`。
5. 用 `doctor.sh --json`、`diagnose_dns.sh --json` 排查问题。语法通过或服务存活不能证明透明代理和 DNS 路径正常。

## 参考文档

| 文档 | 内容 |
| :--- | :--- |
| [architecture-and-schema.md](skills/singbox-openwrt/references/architecture-and-schema.md) | sing-box 架构规范、OpenWrt 硬件防护基线、v1.13 vs v1.14 字段门控与兼容矩阵 |
| [dns-and-routing.md](skills/singbox-openwrt/references/dns-and-routing.md) | RealIP vs FakeIP 机制、DNS 防污染、Canary 域名阻断与多级解析防环 |
| [openwrt-pitfalls-and-troubleshooting.md](skills/singbox-openwrt/references/openwrt-pitfalls-and-troubleshooting.md) | OpenWrt 闪存寿命保护、防火墙 tun0 放行、常见症状与排障速查索引 |
| [modular-blocks.md](skills/singbox-openwrt/references/modular-blocks.md) | 模块化规则积木与主路由/旁路由/指定设备分流等复杂拓扑组装指南 |
| [dae-rules-and-syntax.md](skills/dae-openwrt/references/dae-rules-and-syntax.md) | dae 配置约束、路由语法、网卡绑定约束与 DNS 重查白名单 |
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
├── docs/                     # 架构、兼容性与历史验证记录
├── reports/hardware/         # R2S 真机审计、用例台账与脱敏证据
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
- 部署前保留快照；回滚结果需核对文件、服务和实际流量；
- 缓存文件固定放在 `/tmp` 下，避免向闪存写入；
- TUN 模式需要在防火墙中放行 `tun0`；
- dae 需要内核 5.15+ 与 BTF，不满足时建议改用 sing-box。

## 使用限制

- 模板区分 sing-box 1.13 和 1.14 字段。升级引擎后，应重新生成并在目标版本校验。
- 复杂 Clash YAML 建议安装 PyYAML；标准库降级解析器只支持部分语法。
- 原生 dae 脚本与 daed 面板应选定一个配置管理入口，避免相互覆盖。
- 临时传输和运行缓存放在 `/tmp`；网络恢复快照与启动钩子写入 `/etc`，用于断线或重启后的恢复。
- FakeIP 不能用于解析代理节点自身的真实地址。修改 DNS、IPv6 或旁路由 NAT 前，应核对实际拓扑。
- 发布前检查已跟踪文件中的凭据。`.gitignore` 无法保护已经提交的文件。

更多说明见 [使用限制](docs/warnings-and-limitations.md)。

## 测试

```bash
# 1. 单元回归测试（纯标准库无依赖）
python run_tests.py

# 2. 本地 OpenWrt 自动化流水线测试（支持 Docker 容器或本地 Mock 仿真）
python docker/run_docker_tests.py

# 3. 故障场景矩阵（默认 dry-run；具体覆盖范围见输出）
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
