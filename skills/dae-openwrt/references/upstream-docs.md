# dae 上游官方文档索引

本技能的扁平专题文档是对上游文档的**中文摘要**；需要原文时按下列链接查看。

上游仓库：<https://github.com/daeuniverse/dae>
文档根目录：<https://github.com/daeuniverse/dae/tree/main/docs/zh>

| 主题 | 上游文件 | 对应本技能文档 |
| :--- | :--- | :--- |
| 配置总览 / 示例配置 | `docs/zh/README.md`、仓库根 `example.dae` | [dae_guidelines.md](./dae_guidelines.md) |
| 路由规则语法 | `docs/zh/configuration/routing.md` | [routing-syntax.md](./routing-syntax.md) |
| DNS 配置 | `docs/zh/configuration/dns.md` | [dns-config.md](./dns-config.md) |
| 外部 DNS 联动（AdGuardHome 等） | `docs/zh/configuration/external-dns.md` | [dns-config.md](./dns-config.md) |
| 支持的代理协议与 URI | `docs/zh/proxy-protocols.md` | [proxy-protocols.md](./proxy-protocols.md) |
| 拆分配置文件（include） | `docs/zh/configuration/separate-config.md` | 见下方说明 |
| 内核参数要求 | `docs/zh/user-guide/kernel-parameters.md` | [dae_guidelines.md](./dae_guidelines.md) |
| 热重载与暂停 | `docs/zh/user-guide/reload-and-suspend.md` | 见下方说明 |
| 以守护进程运行 | `docs/zh/user-guide/run-as-daemon.md` | — |
| 内核升级（BTF） | `docs/zh/user-guide/kernel-upgrade.md` | [dae_guidelines.md](./dae_guidelines.md) |
| 自行编译 | `docs/zh/user-guide/build-by-yourself.md` | — |
| 工作原理 | `docs/zh/how-it-works.md` | — |
| 故障排查 | `docs/zh/troubleshooting.md` | [troubleshooting.md](./troubleshooting.md) |

## 两个高频命令（摘自上游 user-guide）

```sh
dae reload      # 重载配置（不断开已建立连接），同时刷新全部订阅
dae suspend     # 暂停劫持（注意：暂停后不再处理 DNS）
dae validate -c /etc/dae/config.dae   # 部署前校验
```

## 拆分配置（include）

大配置可拆分，`include` 的相对路径以**入口配置文件所在目录**为基准，且被包含文件必须位于该目录之下：

```shell
include {
  config.d/*.dae
  /etc/dae/config.d/*.dae
}
```

---

> 与本技能的关系：以上文档版权归 daeuniverse 所有；本仓库不再附带其完整镜像，仅保留摘要与链接，
> 以减小分发体积并避免文档版本漂移。
> 需要离线原文时，可自行浅克隆上游仓库到本机备用：
> `git clone --depth 1 https://github.com/daeuniverse/dae.git`（文档位于 `docs/zh/`）。
