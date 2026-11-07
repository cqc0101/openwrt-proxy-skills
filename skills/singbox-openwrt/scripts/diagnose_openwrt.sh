#!/bin/sh
# ==============================================================================
# OpenWrt 透明代理全链路健康体检医生 (One-Click Diagnostic Doctor)
# 纯 POSIX /bin/sh 编写，无缝兼容 OpenWrt 21.02 / 22.03 / 23.05 / 24.10+
# ==============================================================================

# 彩色输出定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

ERRORS=0
WARNINGS=0

log_header() {
    echo ""
    echo "${CYAN}${BOLD}=== [ $1 ] ===${NC}"
}

log_pass() {
    echo "  ${GREEN}[✓ PASS]${NC} $1"
}

log_warn() {
    echo "  ${YELLOW}[⚠ WARN]${NC} $1"
    WARNINGS=$((WARNINGS + 1))
}

log_fail() {
    echo "  ${RED}[✗ FAIL]${NC} $1"
    ERRORS=$((ERRORS + 1))
}

log_info() {
    echo "  ${BLUE}[i INFO]${NC} $1"
}

echo "${BOLD}================================================================${NC}"
echo "${BOLD}         OpenWrt / ImmortalWrt 透明代理全链路健康诊断报告         ${NC}"
echo "${BOLD}================================================================${NC}"
echo "诊断时间: $(date '+%Y-%m-%d %H:%M:%S')"

# ------------------------------------------------------------------------------
# 1. 硬件环境与系统负载检查
# ------------------------------------------------------------------------------
log_header "1. 硬件架构与系统负载"
MODEL=$(cat /tmp/sysinfo/model 2>/dev/null || uname -m)
KERNEL=$(uname -r)
RAW_ARCH=$(uname -m)

# 借鉴 ShellCrash 架构精准识别体系
case "$RAW_ARCH" in
    x86_64|amd64)
        CPU_ARCH="x86_64 (64位 X86架构)"
        ;;
    i386|i686)
        CPU_ARCH="x86_32 (32位 X86架构)"
        ;;
    aarch64|arm64|armv8*)
        CPU_ARCH="aarch64 (64位 ARMv8架构)"
        ;;
    armv7*|armv6*|arm)
        CPU_ARCH="armv7 (32位 ARM架构)"
        ;;
    mips*|mipsel*)
        # 探测大小端
        if echo -n I | od -to2 2>/dev/null | head -n1 | grep -q "122"; then
            CPU_ARCH="mipsel (32位 MIPS小端架构，如MT7621)"
        else
            CPU_ARCH="mips (32位 MIPS大端架构，如AR9344)"
        fi
        ;;
    *)
        CPU_ARCH="$RAW_ARCH"
        ;;
esac

UPTIME=$(uptime | awk -F'( |,|:)+' '{if ($7=="min") print $6" mins"; else print $6"h "$7"m"}')
LOAD=$(uptime | awk -F'load average:' '{ print $2 }')

log_info "设备型号: $MODEL"
log_info "CPU 架构: $CPU_ARCH"
log_info "内核版本: $KERNEL"
log_info "系统运行时间: $UPTIME | 负载: $LOAD"

# 内存与缓存检查
TOTAL_MEM=$(free -m 2>/dev/null | awk '/Mem:/ {print $2}')
FREE_MEM=$(free -m 2>/dev/null | awk '/Mem:/ {print $4}')
AVAIL_MEM=$(free -m 2>/dev/null | awk '/Mem:/ {print $7}')
[ -z "$AVAIL_MEM" ] && AVAIL_MEM=$FREE_MEM
[ -z "$AVAIL_MEM" ] && AVAIL_MEM=0

if [ "$AVAIL_MEM" -lt 30 ]; then
    log_fail "可用物理内存仅剩 ${AVAIL_MEM}MB (总计 ${TOTAL_MEM}MB)，存在极高 OOM 风险！"
elif [ "$AVAIL_MEM" -lt 60 ]; then
    log_warn "可用物理内存不足 (${AVAIL_MEM}MB/${TOTAL_MEM}MB)，建议精简规则集或挂载 Swap。"
else
    log_pass "内存充裕: 剩余可用 ${AVAIL_MEM}MB / 总计 ${TOTAL_MEM}MB"
fi

# 闪存安全与缓存目录检查
if [ -f "/etc/sing-box-cache.db" ] || [ -f "/etc/sing-box/cache.db" ]; then
    log_warn "发现 cache.db 存储在 /etc 闪存中！长期写入将严重磨损 SPI 闪存！"
else
    log_pass "闪存防护已生效 (未发现 /etc 闪存盘高频写入)"
fi

# ------------------------------------------------------------------------------
# 2. 核心服务运行状态检查
# ------------------------------------------------------------------------------
log_header "2. 代理服务进程状态"

SINGBOX_PID=$(pidof sing-box 2>/dev/null)
DAE_PID=$(pidof dae 2>/dev/null)
DAED_PID=$(pidof daed 2>/dev/null)

if [ -n "$SINGBOX_PID" ]; then
    SINGBOX_VER=$(sing-box version 2>/dev/null | head -n 1)
    SINGBOX_MEM=$(awk '/VmRSS/{print $2}' /proc/$SINGBOX_PID/status 2>/dev/null)
    if [ -n "$SINGBOX_MEM" ] && [ "$SINGBOX_MEM" -gt 0 ] 2>/dev/null; then
        SINGBOX_MEM_MB=$((SINGBOX_MEM / 1024))
    else
        SINGBOX_MEM_MB=0
    fi
    log_pass "sing-box 正在运行 [PID: $SINGBOX_PID, 占用内存: ${SINGBOX_MEM_MB}MB]"
    log_info "版本: $SINGBOX_VER"
elif [ -n "$DAE_PID" ] || [ -n "$DAED_PID" ]; then
    ACTIVE_PID=${DAE_PID:-$DAED_PID}
    log_pass "dae/daed eBPF 引擎正在运行 [PID: $ACTIVE_PID]"
else
    log_fail "未检测到正在运行的科学上网核心进程 (sing-box 或 dae/daed)！"
fi

# Clash API / 控制端口
if command -v netstat >/dev/null 2>&1 && netstat -tuln 2>/dev/null | grep -q ":9090"; then
    log_pass "Clash 外部控制 API 已正常监听在 9090 端口"
else
    log_info "未监听 9090 端口 (若未开启 clash_api 可忽略)"
fi

# ------------------------------------------------------------------------------
# 3. 网卡、接口与内核路由转发
# ------------------------------------------------------------------------------
log_header "3. 网络接口与内核转发"

# 内核转发检查
IP_FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
if [ "$IP_FWD" = "1" ]; then
    log_pass "内核 IPv4 数据包转发已开启 (net.ipv4.ip_forward=1)"
else
    log_fail "内核转发被禁用 (net.ipv4.ip_forward=0)！局域网手机/电脑将无法通过路由器上网！"
    log_info "修复命令: sysctl -w net.ipv4.ip_forward=1"
fi

# TUN 网卡状态
if ip link show tun0 >/dev/null 2>&1; then
    TUN_STATUS=$(ip link show tun0 | grep -o "state [A-Z]*" | awk '{print $2}')
    TUN_IP=$(ip -4 addr show tun0 | grep -o "inet [0-9.]*" | awk '{print $2}')
    log_pass "TUN 网卡 tun0 存在且正常 [状态: $TUN_STATUS, IP: ${TUN_IP:-无}]"
elif [ -n "$DAE_PID" ] || [ -n "$DAED_PID" ]; then
    log_pass "dae 采用原生 eBPF TC/XDP 劫持，无需创建虚拟 TUN 网卡"
else
    log_fail "未发现 tun0 虚拟网卡！sing-box TUN 模式可能启动失败或配置异常！"
fi

# ------------------------------------------------------------------------------
# 4. 防火墙与流量放行 (fw4 / fw3)
# ------------------------------------------------------------------------------
log_header "4. 防火墙与流量放行"

FW_VER="未知"
if command -v fw4 >/dev/null 2>&1; then
    FW_VER="fw4 (nftables)"
elif command -v fw3 >/dev/null 2>&1; then
    FW_VER="fw3 (iptables)"
fi
log_info "当前防火墙框架: $FW_VER"

# 检查 tun0 是否在 firewall 配置中被加入 lan
if uci show firewall 2>/dev/null | grep -q "tun0"; then
    log_pass "OpenWrt 防火墙配置已显式加入 tun0 接口放行"
elif [ -n "$SINGBOX_PID" ]; then
    log_warn "uci firewall 中未明确找到 tun0！若局域网设备无法出海，需放行 tun0。"
    log_info "一键修复: 运行 sh setup_openwrt_firewall.sh"
fi

# ------------------------------------------------------------------------------
# 5. DNS 劫持与闭环解析测试
# ------------------------------------------------------------------------------
log_header "5. DNS 劫持与分流探测"

if ! command -v nslookup >/dev/null 2>&1; then
    log_warn "系统未安装 nslookup，跳过 DNS 解析测试 (可 opkg install bind-host 或 busybox-nslookup 安装)"
else
# 测试 Dnsmasq 本地解析 (BusyBox nslookup 输出兼容，不依赖 grep -A)
DNS_LAN=$(nslookup router.lan 127.0.0.1 2>/dev/null | awk '/Name:/{n=1} n && /Address/{print $2; exit}')
if [ -n "$DNS_LAN" ]; then
    log_pass "本地局域网域名解析正常: router.lan -> $DNS_LAN"
else
    log_warn "本地 router.lan 解析未返回结果 (如果内网使用 IP 访问则无影响)"
fi

# 测试国内域名真实 IP 解析
BAIDU_IP=$(nslookup baidu.com 127.0.0.1 2>/dev/null | awk '/Name:/{n=1} n && /Address/{print $2; exit}')
if [ -n "$BAIDU_IP" ]; then
    log_pass "国内域名解析正常: baidu.com -> $BAIDU_IP"
else
    log_fail "国内 DNS 解析失败 (127.0.0.1:53 无响应或上游超时)！"
fi

# 测试海外域名 FakeIP / 代理解析
GOOGLE_IP=$(nslookup google.com 127.0.0.1 2>/dev/null | awk '/Name:/{n=1} n && /Address/{print $2; exit}')
if [ -n "$GOOGLE_IP" ]; then
    case "$GOOGLE_IP" in
        198.18.*|198.19.*)
            log_pass "出海域名成功被 FakeIP 劫持接管: google.com -> $GOOGLE_IP"
            ;;
        *)
            log_pass "出海域名解析成功 (RealIP 模式): google.com -> $GOOGLE_IP"
            ;;
    esac
else
    log_fail "出海域名解析失败 (google.com 无响应)！"
fi
fi

# ------------------------------------------------------------------------------
# 6. 真实出海出口连通性与地理位置
# ------------------------------------------------------------------------------
log_header "6. 真实出海连通性与落地出口"

OUTBOUND_OK=0
# 探测 Cloudflare HTTP 204（OpenWrt 常缺 curl，wget 兜底）
HTTP_CODE=""
if command -v curl >/dev/null 2>&1; then
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 4 http://cp.cloudflare.com/generate_204 2>/dev/null)
elif command -v wget >/dev/null 2>&1; then
    wget -q -T 4 --spider http://cp.cloudflare.com/generate_204 2>/dev/null && HTTP_CODE="204"
fi
if [ "$HTTP_CODE" = "204" ]; then
    log_pass "出海连通性握手成功 (Cloudflare 204 秒开)"
    OUTBOUND_OK=1
else
    # 备用探测 Google
    HTTP_CODE2=""
    if command -v curl >/dev/null 2>&1; then
        HTTP_CODE2=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 4 https://www.google.com 2>/dev/null)
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 4 --spider https://www.google.com 2>/dev/null && HTTP_CODE2="200"
    fi
    if [ "$HTTP_CODE2" = "200" ] || [ "$HTTP_CODE2" = "301" ] || [ "$HTTP_CODE2" = "302" ]; then
        log_pass "出海连通性握手成功 (Google 访问正常)"
        OUTBOUND_OK=1
    else
        log_fail "无法连通外网！出海握手超时 (HTTP Code: ${HTTP_CODE:-000})"
    fi
fi

if [ "$OUTBOUND_OK" = "1" ]; then
    # 获取出口 IP 与地区
    IP_INFO=""
    if command -v curl >/dev/null 2>&1; then
        IP_INFO=$(curl -s --connect-timeout 4 https://api.ip.sb/geoip 2>/dev/null || curl -s --connect-timeout 4 https://ipinfo.io/json 2>/dev/null)
    elif command -v wget >/dev/null 2>&1; then
        IP_INFO=$(wget -q -T 4 -O - https://api.ip.sb/geoip 2>/dev/null || wget -q -T 4 -O - https://ipinfo.io/json 2>/dev/null)
    fi
    if [ -n "$IP_INFO" ]; then
        IP_ADDR=$(echo "$IP_INFO" | grep -o '"ip":"[^"]*"' | cut -d'"' -f4)
        COUNTRY=$(echo "$IP_INFO" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
        ISP=$(echo "$IP_INFO" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)
        log_info "出口公网 IP: ${IP_ADDR:-未知} (${COUNTRY:-未知} - ${ISP:-未知})"
    fi
fi

# ------------------------------------------------------------------------------
# 7. 诊断总结与结论
# ------------------------------------------------------------------------------
echo ""
echo "${BOLD}================================================================${NC}"
if [ "$ERRORS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
    echo "${GREEN}${BOLD}  【完美】软路由全链路体检全部通过！出海透明代理处于巅峰健康状态！${NC}"
elif [ "$ERRORS" -eq 0 ]; then
    echo "${YELLOW}${BOLD}  【良好】透明代理运行正常，发现 $WARNINGS 处轻微告警 (详见上方黄标提示)。${NC}"
else
    echo "${RED}${BOLD}  【异常】发现 $ERRORS 处阻断性致命错误！请参照上方红标排查！${NC}"
fi
echo "${BOLD}================================================================${NC}"

exit $ERRORS
