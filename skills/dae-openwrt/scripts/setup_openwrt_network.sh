#!/bin/sh
# ==============================================================================
# OpenWrt dae eBPF 最后一公里网络与内核加固工具 (dae Network Hook)
# 彻底闭环：
# 1. 内核转发限制：激活 net.ipv4.ip_forward=1 并按物理内存自适应扩充 nf_conntrack_max
# 2. 流量分载关闭：关闭 flow_offloading，防止报文绕过 eBPF 挂载点
# 3. MSS 钳制 (MSS Clamping)：激活 mtu_fix=1（与防火墙变更合并单次提交，消除 3 次重复 reload）
# 4. 旁路由支持：支持 --bypass 开启 LAN 伪装 (masq=1)，消除非对称路由丢包
# 5. Dnsmasq 纯净过滤：激活 filter_aaaa='1' 根治国内手机 App 打开转圈假死
# 6. 系统性能调优：激活 BBR + fq_codel 算法与 SSH OOM 豁免保护
# 7. 状态快照与安全回滚：支持 --watchdog / --confirm / --revert 一键无损还原原始网络基线
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
            pkill -P "$_wd_pid" 2>/dev/null || true
            kill "$_wd_pid" 2>/dev/null || true
        fi
        rm -f /tmp/proxy_watchdog.pid
    fi
    rm -f /tmp/proxy_watchdog.token
}

# 逆序清理名为 Redirect-DNS-Proxy 的遗留防火墙 redirect 规则，避免干扰 dae 透明劫持
clean_dns_redirects() {
    for r_idx in $(uci show firewall 2>/dev/null | grep -E "=redirect$" | cut -d. -f2 | cut -d= -f1 | awk '{lines[NR]=$0} END {for(i=NR;i>=1;i--) print lines[i]}'); do
        r_name=$(uci get "firewall.${r_idx}.name" 2>/dev/null || true)
        if [ "$r_name" = "Redirect-DNS-Proxy" ]; then
            uci delete "firewall.${r_idx}" 2>/dev/null || true
        fi
    done
}

run_dae_hardening() {
    ACTION_FLAG="${1:-}"

    # 检查因突发断电/内核崩溃遗留的闪存启动哨兵，执行启动即时自愈 (防 /tmp 挥发性失效)
    # 关键判定：仅当闪存 .boot_guard 存在且内存盘 /tmp/proxy_watchdog.token 已挥发丢失时，
    # 才说明系统在看门狗期间发生过硬重启；正常部署中 (token 尚在) 绝不误拦截后续网络配置与 --confirm！
    if [ "$ACTION_FLAG" != "--confirm" ] && [ "$ACTION_FLAG" != "--revert" ] && [ "$ACTION_FLAG" != "--watchdog" ]; then
        if [ -f /etc/dae/.boot_guard ] && [ ! -f /tmp/proxy_watchdog.token ]; then
            say "${RED}[BOOT GUARD] 检测到前序部署未确认且系统发生过硬重启 (/tmp 已挥发)，正在从闪存快照强力恢复配置与网络...${NC}"
            [ -f /etc/dae/.config.dae.rollback ] && cp -f /etc/dae/.config.dae.rollback /etc/dae/config.dae 2>/dev/null || true
            rm -f /etc/dae/.boot_guard /etc/dae/.config.dae.rollback /etc/uci-defaults/99-proxy-boot-guard 2>/dev/null || true
            ( [ -x /etc/init.d/dae ] && /etc/init.d/dae reload 2>/dev/null || dae reload 2>/dev/null ) || true
            run_dae_hardening "--revert" 2>/dev/null || true
            return 0
        fi
    fi

    # 定位 LAN zone 索引
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
        rm -f /etc/dae/.boot_guard /etc/dae/.config.dae.rollback /etc/uci-defaults/99-proxy-boot-guard 2>/dev/null || true
        say "${GREEN}[OK] 已确认新配置连通性正常，本地回滚看门狗与闪存启动哨兵已解除并清理。${NC}"
        return 0
    fi

    if [ "$ACTION_FLAG" = "--watchdog" ]; then
        kill_active_watchdog
        rm -f /tmp/proxy_deploy_confirmed
        _wd_token="wd_$$_$(date +%s 2>/dev/null || echo 1)"
        echo "$_wd_token" > /tmp/proxy_watchdog.token 2>/dev/null || true

        # 闪存持久化防失联哨兵 + OpenWrt uci-defaults 开机自动恢复钩子
        # (根治因突发内核 Panic / 硬件断电导致 /tmp 内存盘挥发失效的边界死穴)
        mkdir -p /etc/dae /etc/uci-defaults 2>/dev/null || true
        if [ -f /etc/dae/config.dae ] && [ ! -f /etc/dae/.config.dae.rollback ]; then
            cp -f /etc/dae/config.dae /etc/dae/.config.dae.rollback 2>/dev/null || true
        fi
        echo "$_wd_token" > /etc/dae/.boot_guard 2>/dev/null || true
        cat << 'BOOTGUARD_EOF' > /etc/uci-defaults/99-proxy-boot-guard 2>/dev/null || true
#!/bin/sh
if [ -f /etc/dae/.boot_guard ] && [ ! -f /tmp/proxy_watchdog.token ]; then
    [ -f /etc/dae/.config.dae.rollback ] && cp -f /etc/dae/.config.dae.rollback /etc/dae/config.dae 2>/dev/null || true
    rm -f /etc/dae/.boot_guard /etc/dae/.config.dae.rollback 2>/dev/null || true
    ( [ -x /etc/init.d/dae ] && /etc/init.d/dae reload 2>/dev/null || dae reload 2>/dev/null ) || true
fi
exit 0
BOOTGUARD_EOF

        say "${YELLOW}[WATCHDOG] 已启动 45 秒本地防失联看门狗 (含闪存启动哨兵防死机)...${NC}"
        (
            sleep 45
            _cur_token=$(cat /tmp/proxy_watchdog.token 2>/dev/null || true)
            if [ ! -f /tmp/proxy_deploy_confirmed ] && [ "$_cur_token" = "$_wd_token" ]; then
                [ -f /etc/dae/.config.dae.rollback ] && cp -f /etc/dae/.config.dae.rollback /etc/dae/config.dae 2>/dev/null || true
                [ -f /tmp/config.dae.bak ] && cp -f /tmp/config.dae.bak /etc/dae/config.dae 2>/dev/null || true
                rm -f /etc/dae/.boot_guard /etc/uci-defaults/99-proxy-boot-guard 2>/dev/null || true
                ( [ -x /etc/init.d/dae ] && /etc/init.d/dae reload 2>/dev/null || dae reload 2>/dev/null ) || true
                run_dae_hardening "--revert" 2>/dev/null || true
            fi
            if [ "$_cur_token" = "$_wd_token" ]; then
                rm -f /tmp/proxy_watchdog.pid /tmp/proxy_watchdog.token 2>/dev/null || true
            fi
        ) </dev/null >/dev/null 2>&1 &
        echo $! > /tmp/proxy_watchdog.pid 2>/dev/null || true
        return 0
    fi

    if [ "$ACTION_FLAG" = "--revert" ]; then
        say "${YELLOW}[REVERT] 正在撤销 dae 网络加固并还原基线...${NC}"
        touch /tmp/proxy_deploy_confirmed 2>/dev/null || true
        kill_active_watchdog
        if [ -f /etc/dae/.config.dae.rollback ]; then
            cp -f /etc/dae/.config.dae.rollback /etc/dae/config.dae 2>/dev/null || true
            rm -f /etc/dae/.config.dae.rollback 2>/dev/null || true
        fi
        rm -f /etc/dae/.boot_guard /etc/uci-defaults/99-proxy-boot-guard 2>/dev/null || true
        if [ -f /etc/dae/.flow_offload.bak ]; then
            . /etc/dae/.flow_offload.bak
            if [ -n "${ORIG_SW_OFFLOAD:-}" ]; then
                uci set "firewall.@defaults[0].flow_offloading=${ORIG_SW_OFFLOAD}" 2>/dev/null || true
            else
                uci delete firewall.@defaults[0].flow_offloading 2>/dev/null || true
            fi
            if [ -n "${ORIG_HW_OFFLOAD:-}" ]; then
                uci set "firewall.@defaults[0].flow_offloading_hw=${ORIG_HW_OFFLOAD}" 2>/dev/null || true
            else
                uci delete firewall.@defaults[0].flow_offloading_hw 2>/dev/null || true
            fi
            rm -f /etc/dae/.flow_offload.bak
        fi
        if [ -f /etc/dae/.network_baseline.bak ]; then
            . /etc/dae/.network_baseline.bak
            if [ -n "$LAN_INDEX" ]; then
                uci delete firewall.@zone[${LAN_INDEX}].masquerade 2>/dev/null || true
                if [ -n "${ORIG_LAN_MASQ:-}" ]; then
                    uci set "firewall.@zone[${LAN_INDEX}].masq=${ORIG_LAN_MASQ}" 2>/dev/null || true
                else
                    uci delete firewall.@zone[${LAN_INDEX}].masq 2>/dev/null || true
                fi
                if [ -n "${ORIG_LAN_MTU_FIX:-}" ]; then
                    uci set "firewall.@zone[${LAN_INDEX}].mtu_fix=${ORIG_LAN_MTU_FIX}" 2>/dev/null || true
                else
                    uci delete firewall.@zone[${LAN_INDEX}].mtu_fix 2>/dev/null || true
                fi
            fi
            if [ -n "${ORIG_FILTER_AAAA:-}" ]; then
                uci set "dhcp.@dnsmasq[0].filter_aaaa=${ORIG_FILTER_AAAA}" 2>/dev/null || true
            else
                uci delete dhcp.@dnsmasq[0].filter_aaaa 2>/dev/null || true
            fi
            rm -f /etc/dae/.network_baseline.bak
        else
            if [ -n "$LAN_INDEX" ]; then
                uci delete firewall.@zone[${LAN_INDEX}].masq 2>/dev/null || true
                uci delete firewall.@zone[${LAN_INDEX}].masquerade 2>/dev/null || true
                uci delete firewall.@zone[${LAN_INDEX}].mtu_fix 2>/dev/null || true
            fi
            uci delete dhcp.@dnsmasq[0].filter_aaaa 2>/dev/null || true
        fi
        uci commit firewall 2>/dev/null || true
        /etc/init.d/firewall reload 2>/dev/null || true
        rm -f /etc/sysctl.d/99-dae.conf /etc/sysctl.d/99-proxy-tuning.conf
        uci commit dhcp 2>/dev/null || true
        /etc/init.d/dnsmasq reload 2>/dev/null || true
        /etc/init.d/sysctl restart 2>/dev/null || sysctl -p 2>/dev/null || true
        say "${GREEN}[OK] 基线还原完成！${NC}"
        return 0
    fi

    mkdir -p /etc/dae
    if [ ! -f /etc/dae/.network_baseline.bak ]; then
        _orig_masq=""
        _orig_mtu=""
        if [ -n "$LAN_INDEX" ]; then
            _orig_masq=$(uci get "firewall.@zone[${LAN_INDEX}].masq" 2>/dev/null | tr -cd '0-9a-zA-Z_.-' || echo "")
            _orig_mtu=$(uci get "firewall.@zone[${LAN_INDEX}].mtu_fix" 2>/dev/null | tr -cd '0-9a-zA-Z_.-' || echo "")
        fi
        _orig_aaaa=$(uci get dhcp.@dnsmasq[0].filter_aaaa 2>/dev/null | tr -cd '0-9a-zA-Z_.-' || echo "")
        printf "ORIG_LAN_MASQ='%s'\nORIG_LAN_MTU_FIX='%s'\nORIG_FILTER_AAAA='%s'\n" "$_orig_masq" "$_orig_mtu" "$_orig_aaaa" > /etc/dae/.network_baseline.bak
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

    say "${BLUE}[1/5] 激活系统 IPv4 路由转发与自适应连接池参数 (nf_conntrack_max=${CONNTRACK_MAX})...${NC}"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null 2>&1
    sysctl -w "net.netfilter.nf_conntrack_max=${CONNTRACK_MAX}" >/dev/null 2>&1 || true

    # 守护进程 OOM 豁免保护：防止内存紧张时内核 OOM Killer 误杀 dropbear/sshd 导致失联
    for _ssh_pid in $(pidof dropbear sshd 2>/dev/null); do
        echo -1000 > "/proc/${_ssh_pid}/oom_score_adj" 2>/dev/null || true
    done

    mkdir -p /etc/sysctl.d
    cat << SYSCTL_EOF > /etc/sysctl.d/99-dae.conf
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
net.netfilter.nf_conntrack_max=${CONNTRACK_MAX}
SYSCTL_EOF

    if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw "bbr"; then
        sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
        sysctl -w net.core.default_qdisc=fq_codel >/dev/null 2>&1 || true
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-dae.conf
        echo "net.core.default_qdisc=fq_codel" >> /etc/sysctl.d/99-dae.conf
    fi

    say "${BLUE}[2/5] 关闭流量分载 (Flow Offloading，防止报文跳过 eBPF 探针)...${NC}"
    if command -v uci >/dev/null 2>&1; then
        if [ ! -f /etc/dae/.flow_offload.bak ]; then
            _sw=$(uci get firewall.@defaults[0].flow_offloading 2>/dev/null | tr -cd '0-9a-zA-Z_.-' || echo "")
            _hw=$(uci get firewall.@defaults[0].flow_offloading_hw 2>/dev/null | tr -cd '0-9a-zA-Z_.-' || echo "")
            printf "ORIG_SW_OFFLOAD='%s'\nORIG_HW_OFFLOAD='%s'\n" "$_sw" "$_hw" > /etc/dae/.flow_offload.bak
        fi
        uci set firewall.@defaults[0].flow_offloading='0' 2>/dev/null || true
        uci set firewall.@defaults[0].flow_offloading_hw='0' 2>/dev/null || true
    fi

    say "${BLUE}[3/5] 开启 LAN 区域 MSS 钳制 (mtu_fix=1)...${NC}"
    if [ -n "$LAN_INDEX" ]; then
        uci set firewall.@zone[${LAN_INDEX}].mtu_fix='1' 2>/dev/null || true
    fi

    if [ "$ACTION_FLAG" = "--bypass" ]; then
        say "${YELLOW}[旁路由] 检测到 --bypass 参数，激活 LAN 区域动态伪装 (masq=1，消除非对称丢包)...${NC}"
        if [ -n "$LAN_INDEX" ]; then
            uci set firewall.@zone[${LAN_INDEX}].masq='1' 2>/dev/null || true
            uci delete firewall.@zone[${LAN_INDEX}].masquerade 2>/dev/null || true
        fi
    fi

    # 清理遗留的本机 53 端口 DNAT 重定向规则并合并提交所有防火墙变更（仅执行 1 次 reload）
    if command -v uci >/dev/null 2>&1; then
        clean_dns_redirects
        uci commit firewall 2>/dev/null || true
        /etc/init.d/firewall reload 2>/dev/null || true
    fi

    say "${BLUE}[4/5] 配置 Dnsmasq AAAA 过滤 (filter_aaaa=1，纯净 IPv4 模式)...${NC}"
    if uci get dhcp.@dnsmasq[0] >/dev/null 2>&1; then
        uci set dhcp.@dnsmasq[0].filter_aaaa='1' 2>/dev/null || true
        uci commit dhcp 2>/dev/null || true
        /etc/init.d/dnsmasq reload 2>/dev/null || true
    fi

    say "${GREEN}[OK] dae eBPF 运行环境加固完成！${NC}"
}

FIRST_ARG="${1:-}"
if [ -z "$FIRST_ARG" ] || [ "$FIRST_ARG" = "--bypass" ] || [ "$FIRST_ARG" = "--revert" ] || [ "$FIRST_ARG" = "--watchdog" ] || [ "$FIRST_ARG" = "--confirm" ]; then
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

    say "${BLUE}[INFO]${NC} 正在连接路由器 ${SSH_USER}@${ROUTER_IP}:${SSH_PORT} 执行 dae 网络加固..."
    if [ -n "$SSH_KEY" ]; then
        [ -f "$SSH_KEY" ] || { say "${RED}指定的 SSH 密钥文件不存在: $SSH_KEY${NC}"; exit 1; }
        ssh -i "$SSH_KEY" -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -- "${SSH_USER}@${ROUTER_IP}" "sh -s -- ${EXTRA_FLAG}" < "$0"
    else
        ssh -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -- "${SSH_USER}@${ROUTER_IP}" "sh -s -- ${EXTRA_FLAG}" < "$0"
    fi
fi
