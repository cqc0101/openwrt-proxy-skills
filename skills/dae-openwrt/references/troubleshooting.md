# dae 常见故障排查

> 依据 dae 官方 `troubleshooting.md` 与 OpenWrt 实战经验整理，原文见 [upstream-docs.md](./upstream-docs.md)。
> 顺序：先确认「能不能启动」→「能不能劫持」→「能不能解析」→「能不能出海」。

## 启动阶段

### 内核/BTF 不满足

- 需要 Linux ≥ 5.15 且有 BTF（`/sys/kernel/btf/vmlinux` 或 `/usr/lib/debug/boot/vmlinux`）。
- 内核低于 5.17 时 dae 会拒绝启动（eBPF 路由循环依赖 `bpf_loop`）。
- OpenWrt 原版可用第三方源装 `vmlinux-btf`，或自编译开启 `CONFIG_DEBUG_INFO_BTF=y`。

### 无法加载 eBPF 对象

```
load eBPF objects: ... argument list too long
```

常见于用 `clang-13` 自行编译的 dae。改用 `clang-15+` 编译，或直接下载 releases 二进制。
`-D__UNROLL_ROUTE_LOOP` 无效果（该宏在源码中已被注释掉）。

### 残留的 `/run/netns/daens`

在容器（LXC/PVE）等受限环境里，上一次运行可能残留命名 netns 挂载点，`umount` 全部返回 `EINVAL`、
`rm` 返回 `EBUSY`。新版本会识别该特征并自动用 tmpfs 覆盖 `/run/netns` 后启动（会打印告警，且隐藏其它
命名 netns，直到重启）。旧版本报 `failed to create netns: open /run/netns/daens: file exists`。
若自动恢复因权限失败，可在与 dae 相同的挂载命名空间内手动执行：

```bash
sudo mount -t tmpfs -o mode=755 tmpfs /run/netns
sudo systemctl start dae
```

## 劫持生效但没网

### 流量分载 / offload 冲突

OpenWrt 开启 `flow_offloading` 后，报文会绕过内核协议栈与 eBPF 钩子，dae 完全失效：

```sh
uci get firewall.@defaults[0].flow_offloading      # 应为 0
uci set firewall.@defaults[0].flow_offloading='0'
uci set firewall.@defaults[0].flow_offloading_hw='0'
uci commit firewall && /etc/init.d/firewall reload
```

### 防火墙误判

dae 把劫持流量转入私有 netns（`daens`），并在其中打 fwmark `0x8000000`。主机防火墙**看不到**这些包，
所以网上流传的 "放行 fwmark 0x8000000" 规则在主机上匹配不到任何流量，属于无效配置。
主机防火墙真正需要放行的是 dae 自身的出站连接与回注到 WAN 的应答包——默认的 established/related
放行规则已经覆盖。

### 绑定 WAN 后无网络

- 先用 `systemctl stop` 临时停掉防火墙确认是否为防火墙问题。
- 旧版 dae 不支持 PPPoE，请升级到最新版本。

## 局域网客户端异常

### 其它机器 DNS 不工作

1. 确认 `lan_interface` 写对（多网卡用逗号分隔，如 `eth1,docker0`；WAN/LAN 共用同一口则两边都写）。
2. 在客户端验证：

```bash
curl -i 1.1.1.1     # 有响应说明连通
curl -i google.com  # 无响应 → DNS 问题
```

3. 检查 53 端口是否被其它程序占用：

```bash
netstat -ulpen | grep 53
# 或 lsof -i:53 -n
```

4. 占用时停用该服务或改端口，并确认 `/etc/resolv.conf` 指向可用 DNS（如 `nameserver 223.5.5.5`，
   不要指向 `127.0.0.1`）。

### `dae suspend` 后无网络

暂停后 dae 不再劫持 DNS。因此**不要**把 dae 主机设为 DHCP 下发的 DNS 服务器，临时停用会直接断解析；
可改用 `223.5.5.5` 等公共 DNS。

## 出海异常

| 现象 | 先查 | 常见原因 |
| :--- | :--- | :--- |
| 全部节点不通 | `dae validate -c /etc/dae/config.dae` | 配置语法/选项名错误（新版本对未知参数名会直接失败） |
| 部分节点不通 | 节点 URI 是否含 IPv6 未加方括号、密码/SNI 是否被转义 | URI 拼接错误 |
| 国内域名也走了代理 | `!domain(...)` 是否拆成了多行 | 取反语义变成 OR（见 routing-syntax.md） |
| 解析污染 | `dns.routing.request` 是否把海外域名送国内上游 | 上游选择错误 |
| 反复断流 | `logread \| grep dae`，看是否有 reload/重连尖峰 | 节点健康检查过于频繁或线路不稳 |

## 日志取证

```sh
logread | grep -i dae | tail -n 100
dae validate -c /etc/dae/config.dae     # 部署前必做
```

重点关注：`load eBPF objects`、`failed to`、`btf`、`no such file`、`permission denied`。
