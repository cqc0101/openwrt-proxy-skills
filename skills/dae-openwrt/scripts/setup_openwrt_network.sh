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
umask 077

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

say() { printf '%b\n' "$1"; }

PRIMARY_ACTION=""
DRY_RUN=0
KEEP_IPV6=0
NO_SYSCTL_TUNING=0
for _opt in "$@"; do
    case "$_opt" in
        --bypass|--revert|--watchdog|--confirm) PRIMARY_ACTION="$_opt" ;;
        --dry-run) DRY_RUN=1 ;;
        --keep-ipv6) KEEP_IPV6=1 ;;
        --no-sysctl-tuning) NO_SYSCTL_TUNING=1 ;;
    esac
done

ENGINE=dae
ENGINE_DIR=/etc/dae
ENGINE_REL=etc/dae
ENGINE_CONFIG=etc/dae/config.dae
# Shared, embedded transaction support: works with SSH sh -s and needs no sibling file.
# Recovery code is persisted before any network mutation and never sourced as shell data.
STATE_ROOT=/etc/proxy-skills-network
STATE="$STATE_ROOT/$ENGINE"
HOOK=/etc/init.d/proxy-skills-recovery
APPLY_STARTED=0

secure_state() {
    [ "$(id -u)" = 0 ] || { say '[ERROR] root required'; return 1; }
    for dep in flock sha256sum tar mktemp uci sysctl; do
        command -v "$dep" >/dev/null 2>&1 || { say "[ERROR] required command missing: $dep"; return 1; }
    done
    if [ ! -e "$STATE_ROOT" ] && [ ! -L "$STATE_ROOT" ]; then
        (umask 077; mkdir -m 700 "$STATE_ROOT") || return 1
    fi
    [ -d "$STATE_ROOT" ] && [ ! -L "$STATE_ROOT" ] &&
        [ "$(ls -ldn "$STATE_ROOT" | awk '{print $1 ":" $3}')" = drwx------:0 ] || {
        say '[ERROR] unsafe transaction directory'; return 1;
    }
    [ ! -L "$STATE_ROOT/lock" ] || return 1
    exec 9>"$STATE_ROOT/lock"
    flock -n 9 || { say '[ERROR] another network operation is running'; return 1; }
    if [ -f "$STATE_ROOT/owner" ] && [ "$(cat "$STATE_ROOT/owner")" != "$ENGINE" ]; then
        say '[ERROR] another engine owns the pending network baseline; revert it first'
        return 1
    fi
    if [ -e "$STATE" ] || [ -L "$STATE" ]; then
        [ -d "$STATE" ] && [ ! -L "$STATE" ] &&
            [ "$(ls -ldn "$STATE" | awk '{print $1 ":" $3}')" = drwx------:0 ] || return 1
    fi
}

current_files() {
    for f in /etc/config/firewall /etc/config/dhcp /etc/sysctl.d/99-singbox.conf /etc/sysctl.d/99-dae.conf /etc/sysctl.d/99-proxy-tuning.conf; do
        if [ -f "$f" ] && [ ! -L "$f" ]; then sha256sum "$f"; else printf 'ABSENT %s\n' "$f"; fi
    done
}

verify_current() {
    [ -f "$STATE/applied" ] || return 0
    tmp=$(mktemp "$STATE/.current.XXXXXX")
    current_files > "$tmp"
    a=$(sha256sum "$tmp"); b=$(sha256sum "$STATE/applied")
    rm -f "$tmp"
    [ "${a%% *}" = "${b%% *}" ] || {
        say '[ERROR] external configuration changes detected; baseline retained for manual reconciliation'
        return 1
    }
}

snapshot_prepare() {
    if pidof "$ENGINE" >/dev/null 2>&1 && [ ! -x "/etc/init.d/$ENGINE" ]; then
        say '[ERROR] running engine has no init service; install a recoverable service before network takeover'
        return 1
    fi
    if [ -f "$STATE/ready" ]; then
        (cd "$STATE" && sha256sum -c snapshot.sha256 >/dev/null) || return 1
        verify_current || return 1
        return 0
    fi
    [ ! -e "$STATE" ] || { say '[ERROR] incomplete snapshot retained; inspect before retry'; return 1; }
    # Refuse to mix a legacy partial backup with the new complete snapshot.
    [ ! -f "$ENGINE_DIR/.network_baseline.bak" ] || {
        say '[ERROR] legacy baseline requires manual recovery before a new deployment'; return 1;
    }
    [ ! -e "$HOOK" ] && [ ! -L "$HOOK" ] || { say '[ERROR] recovery hook already exists'; return 1; }
    mkdir -m 700 "$STATE"
    printf '%s\n' "$ENGINE" > "$STATE_ROOT/owner"
    : > "$STATE/present"; : > "$STATE/absent"
    for f in etc/config/firewall etc/config/dhcp etc/sysctl.d/99-singbox.conf etc/sysctl.d/99-dae.conf etc/sysctl.d/99-proxy-tuning.conf "$ENGINE_CONFIG" "$ENGINE_REL/.network_baseline.bak" "$ENGINE_REL/.dnsmasq_upstream.bak" "$ENGINE_REL/.flow_offload.bak"; do
        [ ! -L "/$f" ] || { say '[ERROR] symlink target refused'; return 1; }
        if [ -e "/$f" ]; then
            [ -f "/$f" ] || return 1
            printf '%s\n' "$f" >> "$STATE/present"
        else
            printf '%s\n' "$f" >> "$STATE/absent"
        fi
    done
    tar -cf "$STATE/snapshot.tar" -C / -T "$STATE/present"
    (cd "$STATE" && sha256sum snapshot.tar present absent > snapshot.sha256)
    : > "$STATE/sysctl"
    for k in net.ipv4.ip_forward net.ipv4.conf.all.forwarding net.ipv4.conf.all.route_localnet net.netfilter.nf_conntrack_max net.ipv4.tcp_congestion_control net.core.default_qdisc net.ipv4.tcp_tw_reuse; do
        v=$(sysctl -n "$k" 2>/dev/null) || continue
        printf '%s=%s\n' "$k" "$v" >> "$STATE/sysctl"
    done
    if pidof "$ENGINE" >/dev/null 2>&1; then printf '1\n'; else printf '0\n'; fi > "$STATE/running"
    [ "$(cat "$STATE/running")" != 1 ] || [ -x "/etc/init.d/$ENGINE" ] || return 1
    printf '%s\n' "$ENGINE" > "$STATE/engine"
    cat > "$STATE/recovery.sh" <<'RECOVERY_EOF'
#!/bin/sh
set -eu
umask 077
D=${0%/*}
ROOT=${D%/*}
ENGINE=$(cat "$D/engine")
case "$ENGINE" in sing-box|dae) ;; *) exit 1 ;; esac
# Validate all backup metadata before touching a live file; retain evidence on any error.
(cd "$D" && sha256sum -c snapshot.sha256 >/dev/null)
if [ -f "$D/applied" ]; then
    tmp=$(mktemp "$D/.current.XXXXXX")
    for f in /etc/config/firewall /etc/config/dhcp /etc/sysctl.d/99-singbox.conf /etc/sysctl.d/99-dae.conf /etc/sysctl.d/99-proxy-tuning.conf; do
        if [ -f "$f" ] && [ ! -L "$f" ]; then sha256sum "$f"; else printf 'ABSENT %s\n' "$f"; fi
    done > "$tmp"
    a=$(sha256sum "$tmp"); b=$(sha256sum "$D/applied")
    rm -f "$tmp"
    [ "${a%% *}" = "${b%% *}" ] || { echo '[RECOVERY FAILED] external configuration changes detected; snapshot retained'; exit 1; }
fi
mkdir -p "$D/extracted"
tar -xf "$D/snapshot.tar" -C "$D/extracted"
while IFS= read -r f; do
    case "$f" in etc/config/firewall|etc/config/dhcp|etc/sysctl.d/99-singbox.conf|etc/sysctl.d/99-dae.conf|etc/sysctl.d/99-proxy-tuning.conf|etc/sing-box/config.json|etc/dae/config.dae|etc/sing-box/.network_baseline.bak|etc/dae/.network_baseline.bak|etc/sing-box/.dnsmasq_upstream.bak|etc/dae/.dnsmasq_upstream.bak|etc/sing-box/.flow_offload.bak|etc/dae/.flow_offload.bak) ;; *) exit 1 ;; esac
    [ ! -L "/$f" ] || exit 1
    dest="/${f%/*}"
    mkdir -p "$dest"
    tmp=$(mktemp "$dest/.proxy-restore.XXXXXX")
    cp -p "$D/extracted/$f" "$tmp"
    mv -f "$tmp" "/$f"
done < "$D/present"
while IFS= read -r f; do
    case "$f" in etc/config/firewall|etc/config/dhcp) exit 1 ;; etc/sysctl.d/99-singbox.conf|etc/sysctl.d/99-dae.conf|etc/sysctl.d/99-proxy-tuning.conf|etc/sing-box/config.json|etc/dae/config.dae|etc/sing-box/.network_baseline.bak|etc/dae/.network_baseline.bak|etc/sing-box/.dnsmasq_upstream.bak|etc/dae/.dnsmasq_upstream.bak|etc/sing-box/.flow_offload.bak|etc/dae/.flow_offload.bak) rm -f "/$f" ;; *) exit 1 ;; esac
done < "$D/absent"
/etc/init.d/firewall reload
/etc/init.d/dnsmasq reload
while IFS= read -r pair; do sysctl -w "$pair" >/dev/null; done < "$D/sysctl"
# Restart the baseline service only when its configuration was changed.
if [ "$(cat "$D/running")" = 1 ]; then
    [ -x "/etc/init.d/$ENGINE" ] || exit 1
    "/etc/init.d/$ENGINE" restart
    sleep 2
    pidof "$ENGINE" >/dev/null
elif [ -x "/etc/init.d/$ENGINE" ]; then
    "/etc/init.d/$ENGINE" stop
    if pidof "$ENGINE" >/dev/null 2>&1; then exit 1; fi
fi
if [ "$(cat "$D/running")" = 0 ] && pidof "$ENGINE" >/dev/null 2>&1; then
    echo '[RECOVERY FAILED] unexpected unmanaged engine is still running; snapshot retained'
    exit 1
fi
while IFS= read -r f; do
    a=$(sha256sum "$D/extracted/$f"); b=$(sha256sum "/$f")
    [ "${a%% *}" = "${b%% *}" ]
done < "$D/present"
while IFS= read -r f; do [ ! -e "/$f" ] && [ ! -L "/$f" ]; done < "$D/absent"
while IFS= read -r pair; do
    k=${pair%%=*}; expected=${pair#*=}
    [ "$(sysctl -n "$k")" = "$expected" ]
done < "$D/sysctl"
rm -f /etc/rc.d/S99proxy-skills-recovery /etc/rc.d/K10proxy-skills-recovery /etc/init.d/proxy-skills-recovery
# Only fixed, validated engine directories can reach this cleanup.
case "$D" in /etc/proxy-skills-network/sing-box|/etc/proxy-skills-network/dae) ;; *) exit 1 ;; esac
rm -rf "$D"
rm -f "$ROOT/owner"
printf '[RECOVERY] files, sysctl and service state verified\n'
RECOVERY_EOF
    chmod 700 "$STATE/recovery.sh"
    (cd "$STATE" && sha256sum -c snapshot.sha256 >/dev/null)
    (cd "$STATE" && sha256sum sysctl running engine >> snapshot.sha256)
    touch "$STATE/ready"
}

arm_watchdog() {
    snapshot_prepare
    [ ! -f "$STATE/pending" ] || { say '[WATCHDOG] already armed'; return 0; }
    _wd_token="wd_$$_$(date +%s)"
    printf '%s\n' "$_wd_token" > "$STATE/pending"
    cat > "$HOOK" <<'HOOK_EOF'
#!/bin/sh /etc/rc.common
START=99
STOP=10
start() {
    # Persistent recovery is self-contained; it does not depend on /tmp or installed skills.
    for d in /etc/proxy-skills-network/sing-box /etc/proxy-skills-network/dae; do
        [ -f "$d/pending" ] || continue
        exec 9>/etc/proxy-skills-network/lock
        flock 9 || return 1
        sh "$d/recovery.sh" || return 1
    done
}
HOOK_EOF
    chmod 700 "$HOOK"
    "$HOOK" enable
    rm -f "$STATE/armed"
    (
        trap '' HUP
        exec 9>&-
        printf '%s\n' "$_wd_token" > "$STATE/armed"
        sleep 45
        exec 9>"$STATE_ROOT/lock"
        flock 9 || exit 1
        if [ -f "$STATE/pending" ] && [ "$(cat "$STATE/pending")" = "$_wd_token" ]; then
            sh "$STATE/recovery.sh" >"$STATE_ROOT/last-recovery.log" 2>&1
        fi
    ) </dev/null >/dev/null 2>&1 &
    _wd_wait=0
    while [ ! -f "$STATE/armed" ] || [ "$(cat "$STATE/armed")" != "$_wd_token" ]; do
        _wd_wait=$((_wd_wait + 1))
        [ "$_wd_wait" -lt 5 ] || { say '[ERROR] watchdog did not acknowledge startup; apply blocked'; return 1; }
        sleep 1
    done
    say '[WATCHDOG] 45 seconds; confirmation requires a fresh connection and business checks'
}

kill_active_watchdog() {
    # Revoke a private token. Never kill a PID read from a shared temporary file.
    rm -f "$STATE/pending"
}

transaction_exit() {
    _rc=$?
    trap - EXIT
    if [ "$_rc" -ne 0 ] && [ "$APPLY_STARTED" -eq 1 ] && [ -f "$STATE/ready" ]; then
        say '[ERROR] apply failed; attempting verified recovery'
        sh "$STATE/recovery.sh" || say '[ERROR] RECOVERY FAILED; snapshot and recovery hook retained'
    fi
    exit "$_rc"
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
    PREVIEW_ACTION="${ACTION_FLAG:-normal}"
    if [ "$DRY_RUN" -eq 1 ]; then
        say "[DRY-RUN] action=${PREVIEW_ACTION}, keep_ipv6=${KEEP_IPV6}, no_sysctl_tuning=${NO_SYSCTL_TUNING}; no changes"
        return 0
    fi

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

    if [ "$ACTION_FLAG" = "--confirm" ]; then
        [ -f "$STATE/ready" ] || { say '[CONFIRM] no pending deployment'; return 1; }
        (cd "$STATE" && sha256sum -c snapshot.sha256 >/dev/null)
        kill_active_watchdog
        "$HOOK" disable 2>/dev/null || true
        rm -f "$HOOK"
        say '[CONFIRM] watchdog disarmed; complete baseline retained for --revert'
        return 0
    fi
    if [ "$ACTION_FLAG" = "--watchdog" ]; then
        arm_watchdog
        return 0
    fi
    if [ "$ACTION_FLAG" = "--revert" ]; then
        if [ ! -f "$STATE/ready" ]; then
            say '[REVERT] no complete baseline; no configuration changed'
            return 0
        fi
        sh "$STATE/recovery.sh"
        return 0
    fi

    if [ -z "$LAN_INDEX" ] && ( [ "$DRY_RUN" -eq 0 ] || [ -f /etc/config/firewall ] ); then
        say "${RED}[ERROR] 未在 /etc/config/firewall 中找到 lan zone！${NC}"
        return 1
    fi



    snapshot_prepare
    APPLY_STARTED=1
    arm_watchdog
    rm -f "$STATE/applied"

    mkdir -p /etc/dae
    if [ ! -f /etc/dae/.network_baseline.bak ]; then
        _orig_masq=""
        _orig_mtu=""
        if [ -n "$LAN_INDEX" ]; then
            _orig_masq=$(uci get "firewall.@zone[${LAN_INDEX}].masq" 2>/dev/null | tr -cd '0-9a-zA-Z_.-' || echo "")
            _orig_mtu=$(uci get "firewall.@zone[${LAN_INDEX}].mtu_fix" 2>/dev/null | tr -cd '0-9a-zA-Z_.-' || echo "")
        fi
        _orig_aaaa=$(uci get dhcp.@dnsmasq[0].filter_aaaa 2>/dev/null | tr -cd '0-9a-zA-Z_.-' || echo "")
        _orig_ipfwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null | tr -cd '0-9' || echo "")
        _orig_ctmax=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null | tr -cd '0-9' || echo "")
        _orig_tcpcc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | tr -cd '0-9a-zA-Z_-' || echo "")
        _orig_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null | tr -cd '0-9a-zA-Z_-' || echo "")
        printf "ORIG_LAN_MASQ='%s'\nORIG_LAN_MTU_FIX='%s'\nORIG_FILTER_AAAA='%s'\nORIG_IP_FORWARD='%s'\nORIG_CONNTRACK_MAX='%s'\nORIG_TCP_CC='%s'\nORIG_DEFAULT_QDISC='%s'\n" "$_orig_masq" "$_orig_mtu" "$_orig_aaaa" "$_orig_ipfwd" "$_orig_ctmax" "$_orig_tcpcc" "$_orig_qdisc" > /etc/dae/.network_baseline.bak
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
    [ "$NO_SYSCTL_TUNING" -eq 0 ] && sysctl -w "net.netfilter.nf_conntrack_max=${CONNTRACK_MAX}" >/dev/null 2>&1 || true


    mkdir -p /etc/sysctl.d
    cat << SYSCTL_EOF > /etc/sysctl.d/99-dae.conf
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
SYSCTL_EOF

    if [ "$NO_SYSCTL_TUNING" -eq 0 ]; then
        echo "net.netfilter.nf_conntrack_max=${CONNTRACK_MAX}" >> /etc/sysctl.d/99-dae.conf
        if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw "bbr"; then
            sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
            sysctl -w net.core.default_qdisc=fq_codel >/dev/null 2>&1 || true
            echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-dae.conf
            echo "net.core.default_qdisc=fq_codel" >> /etc/sysctl.d/99-dae.conf
        fi
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
    elif [ -n "$LAN_INDEX" ] && [ -f /etc/dae/.network_baseline.bak ]; then
        . /etc/dae/.network_baseline.bak
        if [ -n "${ORIG_LAN_MASQ:-}" ]; then
            uci set "firewall.@zone[${LAN_INDEX}].masq=${ORIG_LAN_MASQ}" 2>/dev/null || true
        else
            uci delete firewall.@zone[${LAN_INDEX}].masq 2>/dev/null || true
        fi
        uci delete firewall.@zone[${LAN_INDEX}].masquerade 2>/dev/null || true
    fi

    # 清理遗留的本机 53 端口 DNAT 重定向规则并合并提交所有防火墙变更（仅执行 1 次 reload）
    if command -v uci >/dev/null 2>&1; then
        clean_dns_redirects
        uci commit firewall
        if command -v fw4 >/dev/null 2>&1; then fw4 check; fi
    /etc/init.d/firewall reload
    fi

    say "${BLUE}[4/5] 配置 Dnsmasq AAAA 过滤 (filter_aaaa=1，纯净 IPv4 模式)...${NC}"
    if uci get dhcp.@dnsmasq[0] >/dev/null 2>&1; then
        if [ "$KEEP_IPV6" -eq 0 ]; then
            uci set dhcp.@dnsmasq[0].filter_aaaa='1' 2>/dev/null || true
        else
            [ -f /etc/dae/.network_baseline.bak ] && . /etc/dae/.network_baseline.bak
            _restore_aaaa="${ORIG_FILTER_AAAA:-${_orig_aaaa:-}}"
            if [ -n "$_restore_aaaa" ]; then
                uci set "dhcp.@dnsmasq[0].filter_aaaa=${_restore_aaaa}" 2>/dev/null || true
            else
                uci delete dhcp.@dnsmasq[0].filter_aaaa 2>/dev/null || true
            fi
        fi
        uci commit dhcp
        /etc/init.d/dnsmasq reload
    fi

    current_files > "$STATE/.applied.new"
    mv -f "$STATE/.applied.new" "$STATE/applied"
    say "${GREEN}[OK] dae 网络配置已应用；请验证引擎、DNS 与实际流量路径后再执行 --confirm。${NC}"
}

FIRST_ARG="${1:-}"
if [ -z "$FIRST_ARG" ] || [ "$FIRST_ARG" = "--bypass" ] || [ "$FIRST_ARG" = "--revert" ] || [ "$FIRST_ARG" = "--watchdog" ] || [ "$FIRST_ARG" = "--confirm" ] || [ "$FIRST_ARG" = "--dry-run" ] || [ "$FIRST_ARG" = "--keep-ipv6" ] || [ "$FIRST_ARG" = "--no-sysctl-tuning" ]; then
    _primary_count=0
    for _arg in "$@"; do
        case "$_arg" in
            --bypass|--watchdog|--confirm|--revert) _primary_count=$((_primary_count + 1)) ;;
            --dry-run|--keep-ipv6|--no-sysctl-tuning) ;;
            *) say '[ERROR] unsupported local argument'; exit 2 ;;
        esac
    done
    [ "$_primary_count" -le 1 ] || { say '[ERROR] conflicting actions'; exit 2; }
    if [ "$DRY_RUN" -eq 0 ]; then
        secure_state
        trap transaction_exit EXIT
    fi
    run_dae_hardening "$PRIMARY_ACTION"
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
                EXTRA_FLAG="${EXTRA_FLAG:+$EXTRA_FLAG }$1"
                ;;
            --dry-run|--keep-ipv6|--no-sysctl-tuning)
                EXTRA_FLAG="${EXTRA_FLAG:+$EXTRA_FLAG }$1"
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

        if [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
        say "${RED}[ERROR] SSH 端口超出合法范围 (1-65535): $SSH_PORT${NC}"
        exit 1
    fi

    say "${BLUE}[INFO]${NC} 正在连接路由器 ${SSH_USER}@${ROUTER_IP}:${SSH_PORT} 执行 dae 网络加固..."
    if [ -n "$SSH_KEY" ]; then
        case "$SSH_KEY" in
            -*|*[[:space:]]*)
                say "${RED}[ERROR] 非法的 SSH 密钥路径: $SSH_KEY${NC}"
                exit 1
                ;;
        esac
        [ -f "$SSH_KEY" ] || { say "${RED}指定的 SSH 密钥文件不存在: $SSH_KEY${NC}"; exit 1; }
        if [ "${OPENWRT_STRICT_SSH:-${OPENWRT_SSH_STRICT_HOST_KEY:-0}}" = "1" ]; then
            ssh -i "$SSH_KEY" -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=yes -o LogLevel=ERROR -- "${SSH_USER}@${ROUTER_IP}" "sh -s -- ${EXTRA_FLAG}" < "$0"
        else
            ssh -i "$SSH_KEY" -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -- "${SSH_USER}@${ROUTER_IP}" "sh -s -- ${EXTRA_FLAG}" < "$0"
        fi
    else
        if [ "${OPENWRT_STRICT_SSH:-${OPENWRT_SSH_STRICT_HOST_KEY:-0}}" = "1" ]; then
            ssh -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=yes -o LogLevel=ERROR -- "${SSH_USER}@${ROUTER_IP}" "sh -s -- ${EXTRA_FLAG}" < "$0"
        else
            ssh -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -- "${SSH_USER}@${ROUTER_IP}" "sh -s -- ${EXTRA_FLAG}" < "$0"
        fi
    fi
fi
