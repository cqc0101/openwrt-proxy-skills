# OpenWrt / ImmortalWrt / iStoreOS 软路由代理配置 Skills

面向 OpenWrt、ImmortalWrt、iStoreOS 的 Agent Skills，用于 sing-box 与 dae 两种透明代理方案的配置生成、部署与排障。

更新记录见 [CHANGELOG.md](CHANGELOG.md)。

## 包含的技能

| 技能 | 引擎 | 说明 |
| :--- | :--- | :--- |
| [`singbox-openwrt`](skills/singbox-openwrt/SKILL.md) | sing-box 1.13 / 1.14+（TUN，FakeIP / RealIP） | 对内核与固件版本要求较低，作为默认方案 |
| [`dae-openwrt`](skills/dae-openwrt/SKILL.md) | dae / daed（eBPF） | 需要 Linux 5.15+ 与 BTF，适用于满足条件的固件 |

技能按 `skills/<技能名>/SKILL.md` 组织，符合常见 Agent Skills 分发约定（`npx skills add`、anthropics/skills）。

## 工作流

1. **环境检测**（`probe.sh` / `probe.ps1`）：发行版、包管理器（实际检测 opkg 或 apk）、内核与 BTF、内存与存储空间、冲突插件。
2. **配置生成**（`auto_config.py`、`sub_parser.py`、`sub_to_dae.py`）：订阅解析与清洗、按 sing-box 版本选择模板、规则集镜像、生成后静态校验。
3. **部署**（`deploy_*.sh` / `deploy_*.ps1`）：远端校验、配置快照、热重载、存活检查、失败回滚。
4. **系统调优**（`optimize_network.sh`）：BBR 与连接数相关参数。
5. **诊断**（`diagnose_openwrt.sh`、`doctor.sh`）：链路检查与日志模式分析。

## 参考文档

| 文档 | 内容 |
| :--- | :--- |
| [compat-matrix.md](skills/singbox-openwrt/references/compat-matrix.md) | OpenWrt 版本与包管理器、sing-box 1.13–1.15 字段差异、dae 运行前提；仅收录对照官方来源确认过的内容 |
| [troubleshooting-index.md](skills/singbox-openwrt/references/troubleshooting-index.md) | 症状、排查命令、常见原因与处理方式，共 7 类 |
| [china-scenarios.md](skills/singbox-openwrt/references/china-scenarios.md) | 机场订阅、光猫桥接、旁路由、IPv6、Clash 面板、多拨等场景 |

## 目录结构

```
.
├── skills/                   # 可分发给 Agent 的技能包（符合 SKILL.md 目录约定）
│   ├── singbox-openwrt/      # sing-box 技能
│   │   ├── SKILL.md
│   │   ├── assets/templates/ # 4 个基准模板（1.13/1.14 × FakeIP/RealIP）
│   │   ├── scripts/          # 生成 / 部署 / 诊断脚本
│   │   └── references/       # 兼容矩阵、排障索引、场景说明、版本字段、节点转换
│   └── dae-openwrt/          # dae 技能
│       ├── SKILL.md
│       ├── assets/templates/ # openwrt.dae 基准模板
│       ├── scripts/
│       └── references/       # 路由语法、DNS、协议、排错、上游索引（均为一级深度）
├── tests/                    # 回归测试（unittest，无第三方依赖）
├── run_tests.py              # 一键回归入口
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

## 测试

```bash
python run_tests.py
```

测试覆盖：模板字段与引用完整性、节点解析、订阅清洗、生成器端到端与静态校验、两个检查脚本、文档链接、shell 语法与行尾规范。GitHub Actions 在推送与 PR 时对多个 Python 版本执行同一套测试。

## 致谢与第三方内容

第三方内容的版权说明见 [NOTICE.md](NOTICE.md)。

- sing-box：<https://github.com/SagerNet/sing-box>。`singbox-openwrt` 的模板骨架参考 [shpirt/singbox-config](https://github.com/shpirt/singbox-config) 修改而来。
- dae / daed：<https://github.com/daeuniverse/dae>。`dae-openwrt/references/` 内为 dae 官方文档镜像，版权归 daeuniverse 所有，按原样保留。
- 规则集：<https://github.com/SagerNet/sing-geosite>、<https://github.com/SagerNet/sing-geoip>。

## 声明

- 本项目为个人维护的开源项目，与 OpenWrt、ImmortalWrt、iStoreOS、SagerNet、daeuniverse 等项目没有隶属或合作关系，也不代表上述项目的官方立场。
- 文档中的命令、参数与判断基于公开资料和测试环境整理，不同固件、内核与版本下可能不同，请以实际设备输出为准。
- 本项目不提供任何订阅、节点或代理服务，也不包含可用的服务器地址；模板中的节点与地址均为占位示例。

## 免责声明

本项目仅用于技术学习与合法的网络配置。请遵守所在地法律法规及所使用服务的条款。使用本项目造成的任何直接或间接损失，作者不承担责任。

## License

[MIT](LICENSE)
