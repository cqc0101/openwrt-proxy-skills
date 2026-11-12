# sing-box 真机验证

官方 ARM64 musl 1.14.4 包 SHA-256：b95e25f921dc5e17a4cf13327243d1177642c7e35425bf5372862c477c359f56。摘要与官方发布 API 一致；临时流式上传，不覆盖系统二进制。

FakeIP/RealIP × main/bypass 四个生成配置在设备原生 check 通过；故意损坏的 JSON 被拒绝。测试时的生成配置含旧 API 地址，随后只修改默认 API 监听地址；新回环 API 用同一原生引擎实际启动并验证本机可达、局域网拒绝。最终模板/生成器字段由全量回归验证。

混合 HTTP 入站实际转发到设备本机 uhttpd，获得 664 字节，并有入站/出站日志。此项只证明本机受控 TCP 转发，不证明外网节点、UDP、全屋分流、TProxy 或 LAN 透明代理。

TUN 原生启动明确失败：open /dev/net/tun: no such file or directory。标记 BLOCKED。软件源更新超时，未安装不匹配的内核模块；未声称 TUN 业务通过，也未把此前 x86 Linux 校验冒充本机 ARM64 1.13 验证。

