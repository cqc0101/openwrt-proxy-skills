# 网络接管

两套网络脚本分别真实修改 firewall/dhcp/sysctl 文件与运行参数，执行 fw4 check/reload；实际核查 UCI 值、nft fw4 表及新 SSH 可达。重复应用文件哈希一致；回滚后恢复原始文件。预先存在 tun0、DNS redirect、AAAA 选项与独立 sysctl 文件的场景均通过保留性测试。

网络配置接管通过不代表透明代理业务通过。本机 TUN 缺失，LAN 无物理客户端，IPv6 无公网默认路由，因此完整流量分流、DNS 上游加密、无泄漏、IPv6 防绕过与 TProxy 未得到证明。测试后 nft 中存在独立 inet dnsmasq DNS redirect 表；初始未保存全量 nft 快照，不能证明其全部动态内容前后一致，也不能贸然删除原有规则。

本轮没有更改管理口地址，没有对无关设备或公网目标进行扫描/攻击。

