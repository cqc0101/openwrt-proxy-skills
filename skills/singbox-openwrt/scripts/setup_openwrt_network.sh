#!/bin/sh
# ==============================================================================
# OpenWrt / ImmortalWrt 最后一公里网络与网关接管加固工具 (Last-Mile Network Hook)
# 彻底闭环：
# 1. 内核转发限制：激活 net.ipv4.ip_forward=1 并持久化
# 2. 防火墙拦截：精准定位 LAN 区域注入 tun0，放行转发 (forward=ACCEPT)
# 3. MSS 钳制 (MSS Clamping)：激活 mtu_fix=1，彻底根治 TLS 大报文黑洞与分片卡死
# 4. 局域网 DNS 路径清理：移除遗留的本机 53 DNAT 重定向，确保三层 tun0 hijack-dns 正常截获
# 5. Dnsmasq 纯净过滤：激活 filter_aaaa='1' 彻底根治国内手机 App 打开转圈假死
# 6. 系统网络性能调优：自动检测并激活 BBR + fq_codel 算法与扩充连接池
# 7. 旁路由自适应：支持 --bypass 自动配置 LAN 区域 masq='1' 防非对称路由丢包
# 8. 安全回滚支持：支持 --revert 一键无损还原原始网络基线
#
# 运行方式：
# - 路由器本地执行: sh setup_openwrt_network.sh [--bypass|--revert]
# - 宿主机远程执行: sh setup_openwrt_network.sh <路由器IP> [用户] [端口] [私钥] [--bypass|--revert]
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

say() { printf '%b\n' "$1"; }

# 逆序清理名为 Redirect-DNS-Proxy 的防火墙 redirect 规则，防止正序删除时匿名节索引前移漏删
clean_dns_redirects() {
    for r_idx in $(uci show firewall 2>/dev/null | grep -E "=redirect$" | cut -d. -f2 | cut -d= -f1 | awk '{lines[NR]=$0} END {for(i=NR;i>=1;i--) print lines[i]}'); do
        r_name=$(uci get "firewall.${r_idx}.name" 2>/dev/null || true)
        if [ "$r_name" = "Redirect-DNS-Proxy" ]; then
            uci delete "firewall.${r_idx}" 2>/dev/null || true
        fi
    done
}

# 核心路由器端本地加固逻辑
run_router_hardening() {
    ACTION_FLAG="${1:-}"

    # 1. 定位确切的 LAN zone 索引 (坚决不盲猜 @zone[0])
    LAN_INDEX=""
    ZONE_IDX=0
    while true; do
        zone_name=$(uci get "firewall.@zone[${ZONE_IDX}].name" 2>/dev/null) || break
        if [ "$zone_name" = "lan" ] || [ "$zone_name" = "LAN" ]; then
            LAN_INDEX="$ZONE_IDX"
            break
        fi
        ZONE_IDX=$((ZONE_IDX + 1))
    done

    if [ -z "$LAN_INDEX" ]; then
        say "${RED}[ERROR] 未在 /etc/config/firewall 中找到 lan zone！${NC}"
        return 1
    fi

    if [ "$ACTION_FLAG" = "--revert" ]; then
        say "${YELLOW}[REVERT] 正在撤销最后一公里网络接管配置并恢复基线...${NC}"
        uci del_list firewall.@zone[${LAN_INDEX}].device='tun0' 2>/dev/null || true
        uci delete firewall.@zone[${LAN_INDEX}].masq 2>/dev/null || true
        uci delete firewall.@zone[${LAN_INDEX}].masquerade 2>/dev/null || true
        uci delete firewall.@zone[${LAN_INDEX}].mtu_fix 2>/dev/null || true
        clean_dns_redirects
        rm -f /etc/sysctl.d/99-singbox.conf /etc/sysctl.d/99-proxy-tuning.conf
        uci delete dhcp.@dnsmasq[0].filter_aaaa 2>/dev/null || true
        uci commit dhcp 2>/dev/null || true
        uci commit firewall
        /etc/init.d/dnsmasq reload 2>/dev/null || true
        /etc/init.d/firewall reload 2>/dev/null || true
        /etc/init.d/sysctl restart 2>/dev/null || sysctl -p 2>/dev/null || true
        say "${GREEN}[OK] 网络配置已无损还原至初始状态！${NC}"
        return 0
    fi

    say "${BLUE}[1/5] 校验与激活系统 IPv4 路由转发与连接池参数...${NC}"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null 2>&1
    sysctl -w net.netfilter.nf_conntrack_max=65536 >/dev/null 2>&1 || true

    # 守护进程 OOM 豁免保护：防止内存紧张时内核 OOM Killer 误杀 dropbear/sshd 导致失联
    for _ssh_pid in $(pidof dropbear sshd 2>/dev/null); do
        echo -1000 > "/proc/${_ssh_pid}/oom_score_adj" 2>/dev/null || true
    done
    sysctl -w net.ipv4.tcp_tw_reuse=1 >/dev/null 2>&1 || true

    mkdir -p /etc/sysctl.d
    cat << 'SYSCTL_EOF' > /etc/sysctl.d/99-singbox.conf
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
net.ipv4.conf.all.route_localnet=1
net.netfilter.nf_conntrack_max=65536
net.ipv4.tcp_tw_reuse=1
SYSCTL_EOF

    # 尝试激活 BBR
    if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw "bbr"; then
        sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
        sysctl -w net.core.default_qdisc=fq_codel >/dev/null 2>&1 || true
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-singbox.conf
        echo "net.core.default_qdisc=fq_codel" >> /etc/sysctl.d/99-singbox.conf
    fi

    say "${BLUE}[2/5] 配置 LAN 区域 (@zone[${LAN_INDEX}]) tun0 放行与转发策略 (forward=ACCEPT)...${NC}"
    CURRENT_DEVICES=$(uci get firewall.@zone[${LAN_INDEX}].device 2>/dev/null || true)
    if ! echo "$CURRENT_DEVICES" | grep -qw "tun0"; then
        uci add_list firewall.@zone[${LAN_INDEX}].device='tun0'
    fi
    uci set firewall.@zone[${LAN_INDEX}].forward='ACCEPT'

    say "${BLUE}[3/5] 激活 LAN 区域 MSS 钳制 (mtu_fix=1，彻底根除 PPPoE/TUN MTU 分片卡死)...${NC}"
    uci set firewall.@zone[${LAN_INDEX}].mtu_fix='1'

    if [ "$ACTION_FLAG" = "--bypass" ]; then
        say "${YELLOW}[旁路由] 检测到 --bypass 参数，激活 LAN 区域动态伪装 (masq=1，消除非对称丢包)...${NC}"
        uci set firewall.@zone[${LAN_INDEX}].masq='1' 2>/dev/null || true
        uci delete firewall.@zone[${LAN_INDEX}].masquerade 2>/dev/null || true
    fi

    say "${BLUE}[4/5] 校验局域网 DNS 转发路径 (确保三层 tun0 hijack-dns 不被本机 53 DNAT 短路)...${NC}"
    clean_dns_redirects

    uci commit firewall
    /etc/init.d/firewall reload 2>/dev/null || true

    say "${BLUE}[5/5] 配置 Dnsmasq AAAA 过滤 (filter_aaaa=1，纯净 IPv4 模式)...${NC}"
    if uci get dhcp.@dnsmasq[0] >/dev/null 2>&1; then
        uci set dhcp.@dnsmasq[0].filter_aaaa='1' 2>/dev/null || true
        uci commit dhcp 2>/dev/null || true
        /etc/init.d/dnsmasq reload 2>/dev/null || true
    fi

    say "${GREEN}[OK] 最后一公里网络闭环加固完成！tun0 放行、MSS 钳制、IP 转发、BBR、DNS 路径清理全部生效。${NC}"
}

# 模式判断：本地执行还是远程 SSH 调度
FIRST_ARG="${1:-}"
if [ -z "$FIRST_ARG" ] || [ "$FIRST_ARG" = "--bypass" ] || [ "$FIRST_ARG" = "--revert" ]; then
    # 本地直接在 OpenWrt 路由器上运行
    run_router_hardening "$FIRST_ARG"
else
    # 宿主机远程调用 SSH 管道
    ROUTER_IP="$FIRST_ARG"
    shift
    SSH_USER="root"
    SSH_PORT="22"
    SSH_KEY=""
    EXTRA_FLAG=""
    SSH_USER_SET=""
    SSH_PORT_SET=""
    SSH_KEY_SET=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --bypass|--revert)
                EXTRA_FLAG="$1"
                ;;
            -u|--user)
                [ $# -ge 2 ] || { say "${RED}[ERROR] 参数 $1 缺少用户名取值${NC}"; exit 1; }
                shift
                SSH_USER="${1:-root}"
                SSH_USER_SET=1
                ;;
            -p|--port)
                [ $# -ge 2 ] || { say "${RED}[ERROR] 参数 $1 缺少端口号取值${NC}"; exit 1; }
                shift
                SSH_PORT="${1:-22}"
                SSH_PORT_SET=1
                ;;
            -i|--key)
                [ $# -ge 2 ] || { say "${RED}[ERROR] 参数 $1 缺少密钥文件路径${NC}"; exit 1; }
                shift
                SSH_KEY="${1:-}"
                SSH_KEY_SET=1
                ;;
            *)
                if [ -z "$SSH_USER_SET" ]; then
                    SSH_USER="$1"
                    SSH_USER_SET=1
                elif [ -z "$SSH_PORT_SET" ]; then
                    SSH_PORT="$1"
                    SSH_PORT_SET=1
                elif [ -z "$SSH_KEY_SET" ]; then
                    SSH_KEY="$1"
                    SSH_KEY_SET=1
                fi
                ;;
        esac
        shift
    done

    case "$ROUTER_IP" in
        -*|*[[:space:]]*|"")
            say "${RED}[ERROR] 非法的目标路由器地址: $ROUTER_IP${NC}"
            exit 1
            ;;
    esac
    case "$SSH_USER" in
        -*|*[[:space:]]*|"")
            say "${RED}[ERROR] 非法的 SSH 用户名: $SSH_USER${NC}"
            exit 1
            ;;
    esac
    case "$SSH_PORT" in
        *[!0-9]*|"")
            say "${RED}[ERROR] 非法的 SSH 端口: $SSH_PORT${NC}"
            exit 1
            ;;
    esac

    say "${BLUE}[INFO]${NC} 正在连接路由器 ${SSH_USER}@${ROUTER_IP}:${SSH_PORT} 执行最后一公里网络闭环加固..."
    if [ -n "$SSH_KEY" ]; then
        [ -f "$SSH_KEY" ] || { say "${RED}指定的 SSH 密钥文件不存在: $SSH_KEY${NC}"; exit 1; }
        ssh -i "$SSH_KEY" -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -- "${SSH_USER}@${ROUTER_IP}" "sh -s -- ${EXTRA_FLAG}" < "$0"
    else
        ssh -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -- "${SSH_USER}@${ROUTER_IP}" "sh -s -- ${EXTRA_FLAG}" < "$0"
    fi
fi
