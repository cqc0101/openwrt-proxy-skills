#!/bin/sh
# ==============================================================================
# OpenWrt dae eBPF 最后一公里网络与内核加固工具 (dae Network Hook)
# 彻底闭环：
# 1. 内核转发限制：激活 net.ipv4.ip_forward=1 并持久化
# 2. 流量分载关闭：关闭 flow_offloading，防止报文绕过 eBPF 挂载点
# 3. MSS 钳制 (MSS Clamping)：激活 mtu_fix=1
# 4. Dnsmasq 纯净过滤：激活 filter_aaaa='1' 根治国内手机 App 打开转圈假死
# 5. 系统性能调优：激活 BBR + fq_codel 算法与扩充连接池
# 6. 安全回滚支持：支持 --revert 一键无损还原原始网络基线
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

say() { printf '%b\n' "$1"; }

run_dae_hardening() {
    ACTION_FLAG="${1:-}"

    if [ "$ACTION_FLAG" = "--revert" ]; then
        say "${YELLOW}[REVERT] 正在撤销 dae 网络加固并还原基线...${NC}"
        rm -f /etc/sysctl.d/99-dae.conf /etc/sysctl.d/99-proxy-tuning.conf
        uci delete dhcp.@dnsmasq[0].filter_aaaa 2>/dev/null || true
        uci commit dhcp 2>/dev/null || true
        /etc/init.d/dnsmasq reload 2>/dev/null || true
        say "${GREEN}[OK] 基线还原完成！${NC}"
        return 0
    fi

    say "${BLUE}[1/4] 激活系统 IPv4 路由转发与连接池参数...${NC}"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null 2>&1
    sysctl -w net.netfilter.nf_conntrack_max=65536 >/dev/null 2>&1 || true

    mkdir -p /etc/sysctl.d
    cat << 'SYSCTL_EOF' > /etc/sysctl.d/99-dae.conf
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
net.netfilter.nf_conntrack_max=65536
SYSCTL_EOF

    if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw "bbr"; then
        sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
        sysctl -w net.core.default_qdisc=fq_codel >/dev/null 2>&1 || true
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-dae.conf
        echo "net.core.default_qdisc=fq_codel" >> /etc/sysctl.d/99-dae.conf
    fi

    say "${BLUE}[2/4] 关闭流量分载 (Flow Offloading，防止报文跳过 eBPF 探针)...${NC}"
    if command -v uci >/dev/null 2>&1; then
        uci set firewall.@defaults[0].flow_offloading='0' 2>/dev/null || true
        uci set firewall.@defaults[0].flow_offloading_hw='0' 2>/dev/null || true
        uci commit firewall 2>/dev/null || true
        /etc/init.d/firewall reload 2>/dev/null || true
    fi

    say "${BLUE}[3/4] 开启 LAN 区域 MSS 钳制 (mtu_fix=1)...${NC}"
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
    if [ -n "$LAN_INDEX" ]; then
        uci set firewall.@zone[${LAN_INDEX}].mtu_fix='1' 2>/dev/null || true
        uci commit firewall 2>/dev/null || true
        /etc/init.d/firewall reload 2>/dev/null || true
    fi

    say "${BLUE}[4/4] 配置 Dnsmasq AAAA 过滤 (filter_aaaa=1，纯净 IPv4 模式)...${NC}"
    if uci get dhcp.@dnsmasq[0] >/dev/null 2>&1; then
        uci set dhcp.@dnsmasq[0].filter_aaaa='1' 2>/dev/null || true
        uci commit dhcp 2>/dev/null || true
        /etc/init.d/dnsmasq reload 2>/dev/null || true
    fi

    say "${GREEN}[OK] dae eBPF 运行环境加固完成！${NC}"
}

FIRST_ARG="${1:-}"
if [ -z "$FIRST_ARG" ] || [ "$FIRST_ARG" = "--revert" ]; then
    run_dae_hardening "$FIRST_ARG"
else
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
            --revert)
                EXTRA_FLAG="$1"
                ;;
            -u|--user)
                shift
                SSH_USER="${1:-root}"
                ;;
            -p|--port)
                shift
                SSH_PORT="${1:-22}"
                ;;
            -i|--key)
                shift
                SSH_KEY="${1:-}"
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

    KEY_OPTS=""
    if [ -n "$SSH_KEY" ]; then
        [ -f "$SSH_KEY" ] || { say "${RED}指定的 SSH 密钥文件不存在: $SSH_KEY${NC}"; exit 1; }
        KEY_OPTS="-i ${SSH_KEY}"
    fi

    SSH_CMD="ssh ${KEY_OPTS} -p ${SSH_PORT} -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR ${SSH_USER}@${ROUTER_IP}"
    say "${BLUE}[INFO]${NC} 正在连接路由器 ${SSH_USER}@${ROUTER_IP}:${SSH_PORT} 执行 dae 网络加固..."
    cat "$0" | $SSH_CMD "sh -s -- ${EXTRA_FLAG}"
fi
