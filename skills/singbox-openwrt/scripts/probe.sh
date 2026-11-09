#!/bin/sh
# ==============================================================================
# OpenWrt / ImmortalWrt / iStoreOS 全维环境感知与体检探针 (Reconnaissance Probe)
# 纯 POSIX /bin/sh 编写，无第三方依赖，兼容 opkg/apk 及全版本架构
# 支持标准输出或 JSON 输出 (-j / --json)
# ==============================================================================
# [共享脚本] 本文件与 dae-openwrt/scripts/probe.sh 完全一致，修改需双份同步！

OUTPUT_JSON=0
for arg in "$@"; do
    if [ "$arg" = "-j" ] || [ "$arg" = "--json" ]; then
        OUTPUT_JSON=1
    fi
done

# 彩色定义 (仅在非 JSON 模式下生效)
if [ "$OUTPUT_JSON" -eq 0 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    NC=''
fi

# ------------------------------------------------------------------------------
# 1. 系统发行版与包管理器探针
# ------------------------------------------------------------------------------
DISTRO="OpenWrt"
DISTRO_VER="Unknown"
DISTRO_TARGET="Unknown"
DISTRO_DESC=""

if [ -f /etc/openwrt_release ]; then
    . /etc/openwrt_release
    DISTRO="${DISTRIB_ID:-OpenWrt}"
    DISTRO_VER="${DISTRIB_RELEASE:-Unknown}"
    DISTRO_TARGET="${DISTRIB_TARGET:-Unknown}"
    DISTRO_DESC="${DISTRIB_DESCRIPTION:-} ${DISTRIB_REVISION:-}"
elif [ -f /etc/os-release ]; then
    DISTRO=$(grep "^NAME=" /etc/os-release | cut -d'=' -f2 | tr -d '"')
    DISTRO_VER=$(grep "^VERSION_ID=" /etc/os-release | cut -d'=' -f2 | tr -d '"')
    DISTRO_DESC=$(grep "^PRETTY_NAME=" /etc/os-release | cut -d'=' -f2 | tr -d '"')
fi

# 判断具体变体 (iStoreOS / ImmortalWrt / 原版)
# 真机 iStoreOS 的 DISTRIB_ID 常为 OpenWrt，需结合 DISTRIB_DESCRIPTION 与 /etc/os-release 综合识别
if [ -f /etc/istoreos_release ] || echo "${DISTRO} ${DISTRO_DESC}" | grep -qi "iStoreOS" || grep -qi "iStoreOS" /etc/os-release 2>/dev/null; then
    DISTRO="iStoreOS"
elif echo "${DISTRO} ${DISTRO_DESC}" | grep -qi "ImmortalWrt" || grep -qi "ImmortalWrt" /etc/os-release 2>/dev/null; then
    DISTRO="ImmortalWrt"
else
    DISTRO="OpenWrt"
fi

# 包管理器探测 (opkg vs apk)
PKG_MGR="none"
if command -v apk >/dev/null 2>&1; then
    PKG_MGR="apk"
elif command -v opkg >/dev/null 2>&1; then
    PKG_MGR="opkg"
fi

# ------------------------------------------------------------------------------
# 2. 硬件架构与资源评估 (RAM / ROM)
# ------------------------------------------------------------------------------
MODEL=$(cat /tmp/sysinfo/model 2>/dev/null || uname -m)
RAW_ARCH=$(uname -m)
CPU_ARCH="$RAW_ARCH"

case "$RAW_ARCH" in
    x86_64|amd64)
        CPU_ARCH="x86_64"
        ARCH_DESC="64-bit x86"
        ;;
    i386|i686)
        CPU_ARCH="x86_32"
        ARCH_DESC="32-bit x86"
        ;;
    aarch64|arm64|armv8*)
        CPU_ARCH="aarch64"
        ARCH_DESC="64-bit ARMv8"
        ;;
    armv7*|armv6*|arm)
        CPU_ARCH="armv7"
        ARCH_DESC="32-bit ARM"
        ;;
    mips*|mipsel*)
        if printf 'I' | od -to2 2>/dev/null | head -n1 | grep -q "122"; then
            CPU_ARCH="mipsel"
            ARCH_DESC="32-bit MIPS Little-Endian (e.g. MT7621)"
        else
            CPU_ARCH="mips"
            ARCH_DESC="32-bit MIPS Big-Endian (e.g. AR9344)"
        fi
        ;;
    *)
        ARCH_DESC="Unknown"
        ;;
esac

# 内存评估 (MB)。注意：部分 BusyBox 的 free 不支持 -m（静默忽略、仍输出 KB），
# 统一改读 /proc/meminfo 的 kB 值再除以 1024，并使用参数展开防止空值语法报错。
RAM_KB=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
TOTAL_RAM=$(( ${RAM_KB:-0} / 1024 ))
AV_KB=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null)
AVAIL_RAM=$(( ${AV_KB:-0} / 1024 ))
if [ "$AVAIL_RAM" -eq 0 ]; then
    FR_KB=$(awk '/^MemFree:/ {print $2}' /proc/meminfo 2>/dev/null)
    AVAIL_RAM=$(( ${FR_KB:-0} / 1024 ))
fi
SWAP_KB=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
TOTAL_SWAP=$(( ${SWAP_KB:-0} / 1024 ))

# 闪存/存储评估 (MB)
FREE_ROM=0
if df -m /overlay >/dev/null 2>&1; then
    FREE_ROM=$(df -m /overlay | awk '$NF=="/overlay" {print $(NF-2)}' | tail -n 1)
elif df -m / >/dev/null 2>&1; then
    FREE_ROM=$(df -m / | awk '$NF=="/" {print $(NF-2)}' | tail -n 1)
fi
# 移除非纯数字字符（例如某些 BusyBox df 带 M 或空值），彻底杜绝 bad number
FREE_ROM=$(echo "$FREE_ROM" | tr -cd '0-9')
[ -z "$FREE_ROM" ] && FREE_ROM=0

# ------------------------------------------------------------------------------
# 3. 内核与 eBPF (BTF) 能力探测
# ------------------------------------------------------------------------------
KERNEL_VER=$(uname -r)
KMAJOR=$(echo "$KERNEL_VER" | cut -d. -f1 | tr -cd '0-9')
KMINOR=$(echo "$KERNEL_VER" | cut -d. -f2 | tr -cd '0-9')
[ -z "$KMAJOR" ] && KMAJOR=0
[ -z "$KMINOR" ] && KMINOR=0

KERNEL_GE_515=0
if [ "$KMAJOR" -gt 5 ] || ( [ "$KMAJOR" -eq 5 ] && [ "$KMINOR" -ge 15 ] ); then
    KERNEL_GE_515=1
fi

# BTF 符号探测 (3 级扫描)
HAS_BTF=0
BTF_PATH="none"
if [ -f /sys/kernel/btf/vmlinux ]; then
    HAS_BTF=1
    BTF_PATH="/sys/kernel/btf/vmlinux"
elif [ -f /usr/lib/debug/boot/vmlinux ]; then
    HAS_BTF=1
    BTF_PATH="/usr/lib/debug/boot/vmlinux"
elif [ -f "/usr/lib/debug/boot/vmlinux-$KERNEL_VER" ]; then
    HAS_BTF=1
    BTF_PATH="/usr/lib/debug/boot/vmlinux-$KERNEL_VER"
fi

# 检查 bpftool
HAS_BPFTOOL=0
command -v bpftool >/dev/null 2>&1 && HAS_BPFTOOL=1

# 检查 TUN 模块
HAS_TUN=0
if [ -c /dev/net/tun ] || lsmod 2>/dev/null | grep -q "^tun "; then
    HAS_TUN=1
fi

# 检查 nfqueue 内核模块（sing-box auto_redirect / auto_detect_interface 的自保依赖；
# 缺失时生成配置应使用 --wan-iface 显式指定 WAN 接口，见 validation-report）
NFQUEUE_OK=0
if [ -d /sys/module/nfnetlink_queue ] || lsmod 2>/dev/null | grep -q "nfnetlink_queue"; then
    NFQUEUE_OK=1
fi

# 引擎适配结论
DAE_CAPABLE=0
[ "$KERNEL_GE_515" -eq 1 ] && [ "$HAS_BTF" -eq 1 ] && DAE_CAPABLE=1

SINGBOX_CAPABLE=1 # sing-box TUN 适配全版本 Linux

# ------------------------------------------------------------------------------
# 4. 端口占用与冲突插件扫描
# ------------------------------------------------------------------------------
# 检查 53 端口占用者 (兼容 netstat 与 ss，并检查 dnsmasq port 配置防止 DHCP-only 模式误判)
DNS_PORT_HOLDER="unknown"
PORT53_ACTIVE=0
if command -v netstat >/dev/null 2>&1 && netstat -tuln 2>/dev/null | grep -qE ":53[[:space:]]"; then
    PORT53_ACTIVE=1
elif command -v ss >/dev/null 2>&1 && ss -tuln 2>/dev/null | grep -qE ":53[[:space:]]"; then
    PORT53_ACTIVE=1
fi

if [ "$PORT53_ACTIVE" -eq 1 ]; then
    DM_PORT=$(uci get dhcp.@dnsmasq[0].port 2>/dev/null || echo "53")
    if [ "$DM_PORT" = "53" ] && ( pidof dnsmasq >/dev/null 2>&1 || pgrep -x "dnsmasq" >/dev/null 2>&1 ); then
        DNS_PORT_HOLDER="dnsmasq"
    elif pidof smartdns >/dev/null 2>&1 || pgrep -x "smartdns" >/dev/null 2>&1; then
        DNS_PORT_HOLDER="smartdns"
    elif pidof AdGuardHome >/dev/null 2>&1 || pgrep -x "AdGuardHome" >/dev/null 2>&1 || pgrep -x "adguardhome" >/dev/null 2>&1; then
        DNS_PORT_HOLDER="AdGuardHome"
    elif pidof mosdns >/dev/null 2>&1 || pgrep -x "mosdns" >/dev/null 2>&1; then
        DNS_PORT_HOLDER="mosdns"
    elif pidof sing-box >/dev/null 2>&1 || pgrep -x "sing-box" >/dev/null 2>&1; then
        DNS_PORT_HOLDER="sing-box"
    elif pidof dnsmasq >/dev/null 2>&1 || pgrep -x "dnsmasq" >/dev/null 2>&1; then
        DNS_PORT_HOLDER="dnsmasq"
    else
        DNS_PORT_HOLDER="active(53)"
    fi
fi
[ -z "$DNS_PORT_HOLDER" ] && DNS_PORT_HOLDER="none"

# 检查 Dnsmasq 上游解析配置与潜在回环死锁风险
DNSMASQ_UPSTREAM="default"
DNSMASQ_LOOP_RISK=0
if command -v uci >/dev/null 2>&1; then
    DM_SERVERS=$(uci get dhcp.@dnsmasq[0].server 2>/dev/null || true)
    if [ -n "$DM_SERVERS" ]; then
        DNSMASQ_UPSTREAM="$DM_SERVERS"
        case "$DM_SERVERS" in
            *127.0.0.1*|*::1*)
                DNSMASQ_LOOP_RISK=1
                ;;
        esac
    fi
fi

# 检查冲突插件运行状态（使用精确进程名、procd 状态与真实 UCI 键，杜绝 pgrep -f 误伤命令行参数）
CONFLICT_PLUGINS=""
check_conflict() {
    pname="$1"
    is_active=0
    if pidof "$pname" >/dev/null 2>&1 || pgrep -x "$pname" >/dev/null 2>&1; then
        is_active=1
    elif [ -f "/etc/init.d/$pname" ] && /etc/init.d/"$pname" status 2>/dev/null | grep -qi "running"; then
        is_active=1
    elif command -v uci >/dev/null 2>&1; then
        if [ "$(uci get "${pname}.@global[0].enabled" 2>/dev/null)" = "1" ] || \
           [ "$(uci get "${pname}.config.enable" 2>/dev/null)" = "1" ] || \
           [ "$(uci get "${pname}.config.enabled" 2>/dev/null)" = "1" ]; then
            is_active=1
        fi
    fi
    if [ "$is_active" -eq 1 ]; then
        CONFLICT_PLUGINS="${CONFLICT_PLUGINS}${pname} "
    fi
}
check_conflict "passwall"
check_conflict "passwall2"
check_conflict "openclash"
check_conflict "homeproxy"
check_conflict "nikki"
check_conflict "shadowsocksr"
check_conflict "ssrplus"
check_conflict "clash"
check_conflict "mihomo"
check_conflict "v2ray"
check_conflict "xray"

# 防火墙框架探测
FW_TYPE="unknown"
if command -v fw4 >/dev/null 2>&1; then
    FW_TYPE="fw4"
elif command -v fw3 >/dev/null 2>&1; then
    FW_TYPE="fw3"
fi

# 流量分载 (Flow Offloading) 探测
SW_OFFLOAD="0"
HW_OFFLOAD="0"
if command -v uci >/dev/null 2>&1; then
    SW_OFFLOAD=$(uci get firewall.@defaults[0].flow_offloading 2>/dev/null || echo "0")
    HW_OFFLOAD=$(uci get firewall.@defaults[0].flow_offloading_hw 2>/dev/null || echo "0")
fi

# ------------------------------------------------------------------------------
# 5. TCP 拥塞控制与内核参数
# ------------------------------------------------------------------------------
CURRENT_CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
BBR_AVAILABLE=0
if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw "bbr"; then
    BBR_AVAILABLE=1
elif lsmod 2>/dev/null | grep -qw "tcp_bbr"; then
    BBR_AVAILABLE=1
fi

IP_FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
# 默认路由接口（WAN）：缺 nfqueue 模块的内核上 auto_detect_interface 自保会失效，
# 生成配置时可用 --wan-iface 显式指定该接口
WAN_IF=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
[ -z "$WAN_IF" ] && WAN_IF="unknown"

# ------------------------------------------------------------------------------
# 输出渲染
# ------------------------------------------------------------------------------
# JSON 值转义：剥离 ANSI 颜色代码与不可打印控制字符，转义引号与反斜杠，压平换行
je() {
    ESC=$(printf '\033')
    printf '%s' "$1" \
        | sed "s/${ESC}\[[0-9;]*[a-zA-Z]//g" \
        | tr '\r\n' '  ' \
        | tr -d '\000-\010\013\014\016-\037\177' \
        | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g'
}
CONFLICT_STR=$(echo $CONFLICT_PLUGINS | xargs 2>/dev/null)

if [ "$OUTPUT_JSON" -eq 1 ]; then
    cat << EOF
{
  "distro": {
    "name": "$(je "$DISTRO")",
    "version": "$(je "$DISTRO_VER")",
    "target": "$(je "$DISTRO_TARGET")",
    "package_manager": "$(je "$PKG_MGR")"
  },
  "hardware": {
    "model": "$(je "$MODEL")",
    "arch": "$(je "$CPU_ARCH")",
    "arch_desc": "$(je "$ARCH_DESC")",
    "ram_total_mb": ${TOTAL_RAM:-0},
    "ram_avail_mb": ${AVAIL_RAM:-0},
    "swap_total_mb": ${TOTAL_SWAP:-0},
    "rom_free_mb": ${FREE_ROM:-0}
  },
  "kernel": {
    "version": "$(je "$KERNEL_VER")",
    "kernel_ge_515": $KERNEL_GE_515,
    "has_btf": $HAS_BTF,
    "btf_path": "$(je "$BTF_PATH")",
    "nfqueue_ok": $NFQUEUE_OK,
    "has_bpftool": $HAS_BPFTOOL,
    "has_tun": $HAS_TUN
  },
  "proxy_engines": {
    "dae_capable": $DAE_CAPABLE,
    "singbox_capable": $SINGBOX_CAPABLE,
    "recommended_engine": "$([ "$DAE_CAPABLE" -eq 1 ] && echo "dae" || echo "sing-box")"
  },
  "conflicts": {
    "dns_port_holder": "$(je "$DNS_PORT_HOLDER")",
    "dnsmasq_upstream": "$(je "$DNSMASQ_UPSTREAM")",
    "dnsmasq_loop_risk": $DNSMASQ_LOOP_RISK,
    "active_conflicts": "$(je "$CONFLICT_STR")",
    "firewall": "$(je "$FW_TYPE")",
    "software_flow_offload": "$(je "$SW_OFFLOAD")",
    "hardware_flow_offload": "$(je "$HW_OFFLOAD")"
  },
  "tuning": {
    "ip_forward": $IP_FORWARD,
    "tcp_congestion_control": "$(je "$CURRENT_CC")",
    "bbr_available": $BBR_AVAILABLE,
    "wan_iface": "$(je "$WAN_IF")"
  }
}
EOF
else
    say() { printf '%b\n' "$1"; }

    say "${BOLD}================================================================${NC}"
    say "${BOLD}       OpenWrt / ImmortalWrt / iStoreOS 全维环境探针报告        ${NC}"
    say "${BOLD}================================================================${NC}"
    
    say "${CYAN}[1. 系统与包管理]${NC}"
    say "  - 发行版本: ${GREEN}${DISTRO}${NC} (${DISTRO_VER}, Target: ${DISTRO_TARGET})"
    say "  - 包管理器: ${GREEN}${PKG_MGR}${NC} $([ "$PKG_MGR" = "apk" ] && echo "(新系列/main-SNAPSHOT 版 apk)" || echo "(经典 opkg，24.10 及更早)")"

    say "${CYAN}[2. 硬件与存储资源]${NC}"
    say "  - 设备型号: $MODEL"
    say "  - CPU 架构: ${GREEN}${CPU_ARCH}${NC} (${ARCH_DESC})"
    say "  - 物理内存: 可用 ${AVAIL_RAM}MB / 总计 ${TOTAL_RAM}MB (Swap: ${TOTAL_SWAP}MB)"
    if [ "$FREE_ROM" -lt 15 ]; then
        say "  - 闪存空间: ${RED}剩余仅 ${FREE_ROM}MB！已触发闪存写保护锁定 (/tmp 缓存)${NC}"
    elif [ "$FREE_ROM" -lt 70 ]; then
        say "  - 闪存空间: 剩余 ${FREE_ROM}MB (偏小；安装 sing-box 请用 ${GREEN}sing-box-tiny${NC} ≈39MiB，完整版 ≈62MiB 装不下)"
    else
        say "  - 闪存空间: 剩余 ${FREE_ROM}MB (充裕)"
    fi

    say "${CYAN}[3. 内核与 eBPF / BTF]${NC}"
    say "  - 内核版本: Linux ${KERNEL_VER}"
    if [ "$HAS_BTF" -eq 1 ]; then
        say "  - BTF 符号: ${GREEN}存在${NC} (${BTF_PATH})"
    else
        say "  - BTF 符号: ${YELLOW}缺失${NC} (若运行 dae 需安装 vmlinux-btf 补丁包)"
    fi
    say "  - TUN 网卡: $([ "$HAS_TUN" -eq 1 ] && echo "${GREEN}可用 (/dev/net/tun)${NC}" || echo "${RED}未就绪${NC}")"
    if [ "$NFQUEUE_OK" -eq 1 ]; then
        say "  - nfqueue 模块: ${GREEN}可用${NC} (auto_detect_interface 自保正常)"
    else
        say "  - nfqueue 模块: ${YELLOW}缺失${NC} (TUN 模式已启用纯净 auto_redirect: false 防死锁自环)"
    fi

    say "${CYAN}[4. 科学上网引擎适配能力]${NC}"
    if [ "$DAE_CAPABLE" -eq 1 ]; then
        say "  - dae (eBPF)   : ${GREEN}[完美支持]${NC} 内核与 BTF 满足要求，可获得巅峰性能与最低 CPU 开销"
    else
        say "  - dae (eBPF)   : ${YELLOW}[受限]${NC} $([ "$KERNEL_GE_515" -eq 0 ] && echo "内核 < 5.15" || echo "缺少 BTF 符号")"
    fi
    say "  - sing-box (TUN): ${GREEN}[完美支持]${NC} 兼容所有 Linux 内核与复杂分流协议"

    say "${CYAN}[5. 端口、防火墙与冲突插件]${NC}"
    say "  - 53 端口占用: ${DNS_PORT_HOLDER}"
    if [ "$DNSMASQ_LOOP_RISK" -eq 1 ]; then
        say "  - ${YELLOW}Dnsmasq 上游: ${DNSMASQ_UPSTREAM} (警告: 指向本地回环，请注意防死锁循环)${NC}"
    elif [ "$DNSMASQ_UPSTREAM" != "default" ]; then
        say "  - Dnsmasq 上游: ${DNSMASQ_UPSTREAM}"
    fi
    say "  - 防火墙框架 : ${FW_TYPE} $([ "$FW_TYPE" = "fw4" ] && echo "(nftables)" || echo "(iptables)")"
    if [ -n "$CONFLICT_PLUGINS" ]; then
        say "  - ${RED}冲突警告${NC}   : 检测到正在运行的代理插件 [ ${RED}${CONFLICT_PLUGINS}${NC}]，部署前建议关闭！"
    else
        say "  - 冲突插件检测: ${GREEN}无冲突${NC} (未发现运行中的 PassWall/OpenClash/HomeProxy)"
    fi
    if [ "$SW_OFFLOAD" = "1" ] || [ "$HW_OFFLOAD" = "1" ]; then
        say "  - 流量分载   : ${YELLOW}已开启 (软卸载: $SW_OFFLOAD, 硬卸载: $HW_OFFLOAD)${NC}"
        say "                 ${YELLOW}注意: 部署 dae 时必须关闭流量分载，否则报文绕过 eBPF 导致失效${NC}"
    else
        say "  - 流量分载   : 已关闭 (适合 eBPF 与透明代理)"
    fi

    say "${CYAN}[6. 网络性能与 BBR 评估]${NC}"
    say "  - 默认路由接口: ${GREEN}${WAN_IF}${NC} (生成配置时可作 --wan-iface 参数)"
    say "  - 内核转发开关: $([ "$IP_FORWARD" = "1" ] && echo "${GREEN}开启 (1)${NC}" || echo "${RED}关闭 (0)${NC}")"
    say "  - TCP 拥塞算法: 当前为 ${GREEN}${CURRENT_CC}${NC} $([ "$BBR_AVAILABLE" -eq 1 ] && echo "(内核支持 BBR)" || echo "(内核不支持 BBR)")"
    say "${BOLD}================================================================${NC}"
fi
