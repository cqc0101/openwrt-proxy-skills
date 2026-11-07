# 生成工作流

本文件定义 sing-box 客户端配置生成时的问答流程、默认值和摘要格式。

## 入口判断

- 只有生成意图、没有节点信息：先询问生成方案。
- 已提供节点信息、没有方案：解析节点，使用默认 `1.13 TUN RealIP` 和模板内置默认规则。
- 已提供节点信息和方案：不要重复询问方案。
- 已提供分流/规则诉求：进入自定义规则流程。
- 修改已有配置：不要启动完整向导，只询问当前变更缺失的信息。
- 节点格式无法识别：只询问节点格式或缺失协议字段，不展开其它问题。

节点信息包括 Clash YAML、sing-box outbound JSON、代理分享链接、订阅链接或手工协议参数。

## 交互策略

如果当前运行时支持结构化选择控件且允许使用，优先用控件提问。否则使用简短文本问题。结构化控件只用于选择题；节点、订阅、YAML、JSON 使用普通聊天输入。

不要承诺任何特定 UI 形态。不要声称 skill 可以切换运行模式。

## 标准生成流程

如果用户只有生成意图，询问：

```md
请选择生成方案：

1. `1.13 TUN FakeIP`（默认）
   当前默认正式版本配置，分流确定性最强、冷启动友好，适合大多数软路由用户。

2. `1.13 TUN RealIP`
   使用正式版本的 RealIP 模板，返回真实 IP，适合需要 RealIP 语义（如按真实 IP 分流、内网服务透传）的用户。

3. `1.14 TUN`
   使用 1.14 前瞻字段；选择后继续询问 RealIP 或 FakeIP。

4. `自定义`
   手动选择版本、运行方式、DNS、IPv6、Clash API、selector、规则等。
```

选择 `1.14 TUN` 后继续询问：

- `FakeIP`（默认，与 1.13 默认一致，分流确定性优先）
- `RealIP`（返回真实 IP；不建议仅因 DNS 延迟选择）

选择 `自定义` 后继续询问：

- 版本：`1.14` / `1.13`
- 运行方式：`TUN/VPN` / `system proxy` / `手动 mixed/socks/http`
- 配置级别：`默认推荐` / `高级自定义`

只有用户选择 `高级自定义` 时，才展开 DNS 优化、IPv6、Clash API、服务 selector、平台包名排除、分流规则。默认推荐路径不要询问这些项目。

方案确定但节点缺失时，普通文本询问：

```md
请粘贴节点信息：Clash YAML、分享链接、订阅链接、sing-box outbound JSON 或手工协议参数均可。
```

## 默认推荐

- 版本：`1.13`
- 运行方式：TUN/VPN
- IPv6：IPv4-only
- Clash API：启用
- 服务 selector：启用
- 平台包名排除：不启用
- 分流规则：模板内置默认规则
- 输出：直接返回 JSON

1.13 TUN 默认选择 FakeIP（与 `auto_config.py --dns-mode fakeip` 的默认一致）。RealIP 模板同样可用：1.13 已支持 RealIP 所需的 `dns.reverse_mapping`，但不能使用 1.14 才有的 `dns.optimistic` / `store_dns`。1.13 默认模板通过国内外 DNS 分流、普通 DNS cache、`independent_cache` 和 `store_rdrc` 降低冷查询和污染风险。

1.14 TUN 默认选择 FakeIP。RealIP 仅在用户明确需要真实 IP 语义时选用；FakeIP 不作为 DNS 延迟优化首选。

## 自定义规则触发

默认不单独询问规则方案，直接使用模板内置规则。只有以下情况进入规则问答：

- 用户选择 `自定义 -> 高级自定义 -> 分流规则`
- 用户主动提到“分流、规则、rule、geosite、geoip、服务出口”
- 用户要求某个服务、域名、国家/地区走特定出口

规则问答：

```md
你希望如何自定义分流规则？

1. `按服务`
   例如 AI、Netflix、YouTube、GitHub、Apple、Telegram。

2. `按域名`
   例如 example.com 必须直连或必须代理。

3. `按国家/地区`
   例如 US、JP、SG 走指定出口，CN 直连。

4. `直接描述`
   直接说明目标，我来匹配 rule-set 或生成显式规则。
```

规则细节见 `references/rule-sets.md`。

## 生成前摘要

生成前必须回显摘要。用户已明确要求生成时，摘要后直接生成，不额外确认。

```md
将按以下选择生成配置：
- 方案：1.13 TUN FakeIP
- 节点：已识别 3 个 outbound
- 分流规则：模板内置默认规则
- IPv6：IPv4-only
- Clash API：启用
- 服务 selector：启用
- 默认项：未选择方案，使用默认 1.13 TUN FakeIP
```
