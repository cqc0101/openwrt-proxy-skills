#!/bin/sh
# ==============================================================================
# OpenWrt / ImmortalWrt 最后一公里网络与网关接管加固工具 (Last-Mile Network Hook)
# 彻底闭环：
# 1. 内核转发限制：激活 net.ipv4.ip_forward=1 并按物理内存自适应扩充 nf_conntrack_max
# 2. 防火墙拦截：精准定位 LAN 区域注入 tun0，放行转发 (forward=ACCEPT)
# 3. MSS 钳制 (MSS Clamping)：激活 mtu_fix=1，彻底根治 TLS 大报文黑洞与分片卡死
# 4. 局域网 DNS 路径清理：移除遗留的本机 53 DNAT 重定向，确保三层 tun0 hijack-dns 正常截获
# 5. Dnsmasq 纯净过滤与防旁路：激活 filter_aaaa='1'，二级路由私网 WAN DNS 自动切换公网上游
# 6. 系统网络性能调优：自动检测并激活 BBR + fq_codel 算法与 SSH OOM 豁免保护
# 7. 旁路由自适应：支持 --bypass 自动配置 LAN 区域 masq='1' 防非对称路由丢包
# 8. 状态快照与安全回滚：支持 --watchdog / --confirm / --revert 无损还原原始网络基线
#
# 运行方式：
# - 路由器本地执行: sh setup_openwrt_network.sh [--bypass|--watchdog|--confirm|--revert]
# - 宿主机远程执行: sh setup_openwrt_network.sh <路由器IP> [用户] [端口] [私钥] [--bypass|--watchdog|--confirm|--revert]
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

say() { printf '%b\n' "$1"; }

kill_active_watchdog() {
    if [ -f /tmp/proxy_watchdog.pid ]; then
        _wd_pid=$(cat /tmp/proxy_watchdog.pid 2>/dev/null || true)
        if [ -n "$_wd_pid" ]; then
            kill "$_wd_pid" 2>/dev/null || true
        fi
        rm -f /tmp/proxy_watchdog.pid
    fi
}

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

    if [ "$ACTION_FLAG" = "--confirm" ]; then
        touch /tmp/proxy_deploy_confirmed
        kill_active_watchdog
        say "${GREEN}[OK] 已确认新配置连通性正常，本地回滚看门狗已解除并清理。${NC}"
        return 0
    fi

    if [ "$ACTION_FLAG" = "--watchdog" ]; then
        kill_active_watchdog
        rm -f /tmp/proxy_deploy_confirmed
        say "${YELLOW}[WATCHDOG] 已启动 45 秒本地防失联看门狗 (若 45 秒内未收到 --confirm 将自动回滚配置与网络)...${NC}"
        (
            sleep 45
            if [ ! -f /tmp/proxy_deploy_confirmed ]; then
                [ -f /tmp/config.json.bak ] && cp /tmp/config.json.bak /etc/sing-box/config.json 2>/dev/null || true
                /etc/init.d/sing-box restart 2>/dev/null || true
                run_router_hardening "--revert" 2>/dev/null || true
            fi
            rm -f /tmp/proxy_watchdog.pid 2>/dev/null || true
        ) </dev/null >/dev/null 2>&1 &
        echo $! > /tmp/proxy_watchdog.pid 2>/dev/null || true
        return 0
    fi

    if [ "$ACTION_FLAG" = "--revert" ]; then
        say "${YELLOW}[REVERT] 正在撤销最后一公里网络接管配置并恢复基线...${NC}"
        touch /tmp/proxy_deploy_confirmed 2>/dev/null || true
        kill_active_watchdog
        uci del_list firewall.@zone[${LAN_INDEX}].device='tun0' 2>/dev/null || true
        uci delete firewall.@zone[${LAN_INDEX}].masquerade 2>/dev/null || true
        if [ -f /etc/sing-box/.network_baseline.bak ]; then
            . /etc/sing-box/.network_baseline.bak
            [ -n "${ORIG_LAN_MASQ:-}" ] && uci set "firewall.@zone[${LAN_INDEX}].masq=${ORIG_LAN_MASQ}" 2>/dev/null || uci delete firewall.@zone[${LAN_INDEX}].masq 2>/dev/null || true
            [ -n "${ORIG_LAN_MTU_FIX:-}" ] && uci set "firewall.@zone[${LAN_INDEX}].mtu_fix=${ORIG_LAN_MTU_FIX}" 2>/dev/null || uci delete firewall.@zone[${LAN_INDEX}].mtu_fix 2>/dev/null || true
            [ -n "${ORIG_FILTER_AAAA:-}" ] && uci set "dhcp.@dnsmasq[0].filter_aaaa=${ORIG_FILTER_AAAA}" 2>/dev/null || uci delete dhcp.@dnsmasq[0].filter_aaaa 2>/dev/null || true
            rm -f /etc/sing-box/.network_baseline.bak
        else
            uci delete firewall.@zone[${LAN_INDEX}].masq 2>/dev/null || true
            uci delete firewall.@zone[${LAN_INDEX}].mtu_fix 2>/dev/null || true
            uci delete dhcp.@dnsmasq[0].filter_aaaa 2>/dev/null || true
        fi
        clean_dns_redirects
        rm -f /etc/sysctl.d/99-singbox.conf /etc/sysctl.d/99-proxy-tuning.conf
        if [ -f /etc/sing-box/.dnsmasq_upstream.bak ]; then
            . /etc/sing-box/.dnsmasq_upstream.bak
            if [ -n "${ORIG_NORESOLV:-}" ]; then
                uci set "dhcp.@dnsmasq[0].noresolv=${ORIG_NORESOLV}" 2>/dev/null || true
            else
                uci delete dhcp.@dnsmasq[0].noresolv 2>/dev/null || true
            fi
            uci delete dhcp.@dnsmasq[0].server 2>/dev/null || true
            rm -f /etc/sing-box/.dnsmasq_upstream.bak
        fi
        uci commit dhcp 2>/dev/null || true
        uci commit firewall
        /etc/init.d/dnsmasq reload 2>/dev/null || true
        /etc/init.d/firewall reload 2>/dev/null || true
        /etc/init.d/sysctl restart 2>/dev/null || sysctl -p 2>/dev/null || true
        say "${GREEN}[OK] 网络配置已无损还原至初始状态！${NC}"
        return 0
    fi

    # 首次执行前保存用户原始防火墙与 Dnsmasq 基线，确保 --revert 不误删用户原有配置
    mkdir -p /etc/sing-box
    if [ ! -f /etc/sing-box/.network_baseline.bak ]; then
        _orig_masq=$(uci get "firewall.@zone[${LAN_INDEX}].masq" 2>/dev/null | tr -cd '0-9a-zA-Z_.-' || echo "")
        _orig_mtu=$(uci get "firewall.@zone[${LAN_INDEX}].mtu_fix" 2>/dev/null | tr -cd '0-9a-zA-Z_.-' || echo "")
        _orig_aaaa=$(uci get dhcp.@dnsmasq[0].filter_aaaa 2>/dev/null | tr -cd '0-9a-zA-Z_.-' || echo "")
        printf "ORIG_LAN_MASQ='%s'\nORIG_LAN_MTU_FIX='%s'\nORIG_FILTER_AAAA='%s'\n" "$_orig_masq" "$_orig_mtu" "$_orig_aaaa" > /etc/sing-box/.network_baseline.bak
    fi

    # 按路由器物理内存动态计算安全 nf_conntrack_max，防止小内存设备内核 Slab OOM
    _ram_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    _ram_mb=$(( ${_ram_kb:-0} / 1024 ))
    if [ "$_ram_mb" -gt 0 ] && [ "$_ram_mb" -lt 256 ]; then
        CONNTRACK_MAX=16384
    elif [ "$_ram_mb" -gt 0 ] && [ "$_ram_mb" -lt 512 ]; then
        CONNTRACK_MAX=32768
    else
        CONNTRACK_MAX=65536
    fi

    say "${BLUE}[1/5] 校验与激活系统 IPv4 路由转发与自适应连接池参数 (nf_conntrack_max=${CONNTRACK_MAX})...${NC}"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null 2>&1
    sysctl -w "net.netfilter.nf_conntrack_max=${CONNTRACK_MAX}" >/dev/null 2>&1 || true

    # 守护进程 OOM 豁免保护：防止内存紧张时内核 OOM Killer 误杀 dropbear/sshd 导致失联
    for _ssh_pid in $(pidof dropbear sshd 2>/dev/null); do
        echo -1000 > "/proc/${_ssh_pid}/oom_score_adj" 2>/dev/null || true
    done
    sysctl -w net.ipv4.tcp_tw_reuse=1 >/dev/null 2>&1 || true

    mkdir -p /etc/sysctl.d
    cat << SYSCTL_EOF > /etc/sysctl.d/99-singbox.conf
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
net.ipv4.conf.all.route_localnet=1
net.netfilter.nf_conntrack_max=${CONNTRACK_MAX}
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

    say "${BLUE}[5/5] 配置 Dnsmasq AAAA 过滤与二级路由私网上游防旁路治理...${NC}"
    if uci get dhcp.@dnsmasq[0] >/dev/null 2>&1; then
        uci set dhcp.@dnsmasq[0].filter_aaaa='1' 2>/dev/null || true
        # 二级路由 DHCP 拓扑治理：当 WAN 上游 DNS 为光猫私网 IP 且 Dnsmasq 未显式指定 server 时，
        # Dnsmasq 发往光猫的请求会走物理 WAN 直连链路绕过 tun0。将其切换为公网 223.5.5.5 使其进入 tun0 hijack-dns。
        _RESOLV_FILE="/tmp/resolv.conf.d/resolv.conf.auto"
        [ ! -f "$_RESOLV_FILE" ] && _RESOLV_FILE="/tmp/resolv.conf.auto"
        _DM_SRV=$(uci get dhcp.@dnsmasq[0].server 2>/dev/null || true)
        if [ -z "$_DM_SRV" ] && [ -f "$_RESOLV_FILE" ]; then
            if grep -qE "^nameserver[[:space:]]+(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.)" "$_RESOLV_FILE" 2>/dev/null; then
                say "${YELLOW}[二级路由防旁路] 检测到 WAN 上游 DNS 为私网地址，配置 Dnsmasq 上游为 223.5.5.5 确保进入 tun0 hijack-dns...${NC}"
                if [ ! -f /etc/sing-box/.dnsmasq_upstream.bak ]; then
                    _orig_nr=$(uci get dhcp.@dnsmasq[0].noresolv 2>/dev/null | tr -cd '0-9a-zA-Z_.-' || echo "")
                    printf "ORIG_NORESOLV='%s'\n" "$_orig_nr" > /etc/sing-box/.dnsmasq_upstream.bak
                fi
                uci set dhcp.@dnsmasq[0].noresolv='1' 2>/dev/null || true
                uci delete dhcp.@dnsmasq[0].server 2>/dev/null || true
                uci add_list dhcp.@dnsmasq[0].server='223.5.5.5' 2>/dev/null || true
            fi
        fi
        uci commit dhcp 2>/dev/null || true
        /etc/init.d/dnsmasq reload 2>/dev/null || true
    fi

    say "${GREEN}[OK] 最后一公里网络闭环加固完成！tun0 放行、MSS 钳制、IP 转发、BBR、DNS 路径清理全部生效。${NC}"
}

# 模式判断：本地执行还是远程 SSH 调度
FIRST_ARG="${1:-}"
if [ -z "$FIRST_ARG" ] || [ "$FIRST_ARG" = "--bypass" ] || [ "$FIRST_ARG" = "--revert" ] || [ "$FIRST_ARG" = "--watchdog" ] || [ "$FIRST_ARG" = "--confirm" ]; then
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
            --bypass|--watchdog|--confirm|--revert)
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
