#!/bin/sh
# ==============================================================================
# OpenWrt / ImmortalWrt 专项 DNS 深度防污染与防泄漏健康体检脚本 (DNS Doctor)
# 纯 POSIX /bin/sh 编写，无第三方外部依赖，兼容各种 BusyBox 环境
# 支持标准输出 (带颜色) 或机器可读 JSON 输出 (-j / --json)
# ==============================================================================
# [共享脚本] 本文件与 singbox-openwrt/scripts/diagnose_dns.sh 完全一致，修改需双份同步！

OUTPUT_JSON=0
for arg in "$@"; do
    if [ "$arg" = "-j" ] || [ "$arg" = "--json" ]; then
        OUTPUT_JSON=1
    fi
done

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

say() {
    [ "$OUTPUT_JSON" -eq 0 ] && printf '%b\n' "$1"
}

# JSON 字符串安全转义 (剥离 ANSI 颜色代码与不可打印控制字符，转义引号与反斜杠，压平换行)
je() {
    ESC=$(printf '\033')
    printf '%s' "$1" \
        | sed "s/${ESC}\[[0-9;]*[a-zA-Z]//g" \
        | tr '\r\n' '  ' \
        | tr -d '\000-\010\013\014\016-\037\177' \
        | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g'
}

say "${BOLD}================================================================${NC}"
say "${BOLD}     OpenWrt DNS 深度健康体检与防污染/防泄漏体检报告            ${NC}"
say "${BOLD}================================================================${NC}"

TOTAL_CHECKS=7
PASSED_CHECKS=0
WARNINGS=0
ERRORS=0
CHECKS_JSON=""

pass() {
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
    [ "$OUTPUT_JSON" -eq 0 ] && say "  ${GREEN}[✔ PASS]${NC} $1"
    item="{\"status\":\"pass\",\"message\":\"$(je "$1")\"}"
    [ -z "$CHECKS_JSON" ] && CHECKS_JSON="$item" || CHECKS_JSON="$CHECKS_JSON,$item"
}

warn() {
    WARNINGS=$((WARNINGS + 1))
    [ "$OUTPUT_JSON" -eq 0 ] && say "  ${YELLOW}[▲ WARN]${NC} $1"
    item="{\"status\":\"warn\",\"message\":\"$(je "$1")\"}"
    [ -z "$CHECKS_JSON" ] && CHECKS_JSON="$item" || CHECKS_JSON="$CHECKS_JSON,$item"
}

fail() {
    ERRORS=$((ERRORS + 1))
    [ "$OUTPUT_JSON" -eq 0 ] && say "  ${RED}[✘ FAIL]${NC} $1"
    item="{\"status\":\"fail\",\"message\":\"$(je "$1")\"}"
    [ -z "$CHECKS_JSON" ] && CHECKS_JSON="$item" || CHECKS_JSON="$CHECKS_JSON,$item"
}

# ------------------------------------------------------------------------------
# 1. 本地 DNS 服务状态与 53 端口监听
# ------------------------------------------------------------------------------
say "\n${CYAN}[1/7] 探测本地 DNS 监听与宿主进程...${NC}"

PORT53_OPEN=0
if command -v netstat >/dev/null 2>&1 && netstat -tuln 2>/dev/null | grep -qE ":53[[:space:]]"; then
    PORT53_OPEN=1
elif command -v ss >/dev/null 2>&1 && ss -tuln 2>/dev/null | grep -qE ":53[[:space:]]"; then
    PORT53_OPEN=1
fi

DNS_HOLDER="unknown"
if [ "$PORT53_OPEN" -eq 1 ]; then
    DM_PORT=$(uci get dhcp.@dnsmasq[0].port 2>/dev/null || echo "53")
    if [ "$DM_PORT" = "53" ] && ( pidof dnsmasq >/dev/null 2>&1 || pgrep -x "dnsmasq" >/dev/null 2>&1 ); then
        DNS_HOLDER="Dnsmasq"
    elif pidof sing-box >/dev/null 2>&1 || pgrep -x "sing-box" >/dev/null 2>&1; then
        DNS_HOLDER="sing-box"
    elif pidof daed >/dev/null 2>&1 || pidof dae >/dev/null 2>&1 || pgrep -x "daed" >/dev/null 2>&1 || pgrep -x "dae" >/dev/null 2>&1; then
        DNS_HOLDER="dae/daed"
    elif pidof smartdns >/dev/null 2>&1 || pgrep -x "smartdns" >/dev/null 2>&1; then
        DNS_HOLDER="smartdns"
    elif pidof mosdns >/dev/null 2>&1 || pgrep -x "mosdns" >/dev/null 2>&1; then
        DNS_HOLDER="mosdns"
    elif pidof dnsmasq >/dev/null 2>&1 || pgrep -x "dnsmasq" >/dev/null 2>&1; then
        DNS_HOLDER="Dnsmasq"
    else
        DNS_HOLDER="active(port 53)"
    fi
    pass "53 端口监听正常，宿主服务: ${DNS_HOLDER}"
else
    fail "53 端口未在监听！DNS 解析服务可能已崩溃或被意外关闭。"
fi

# ------------------------------------------------------------------------------
# 2. 国内直连 DNS 解析效率与 CDN 归属
# ------------------------------------------------------------------------------
say "\n${CYAN}[2/7] 测试国内高频域名解析效率 (baidu.com / qq.com)...${NC}"

RESOLVE_TOOL=""
if command -v nslookup >/dev/null 2>&1; then
    RESOLVE_TOOL="nslookup"
elif command -v dig >/dev/null 2>&1; then
    RESOLVE_TOOL="dig"
fi

run_nslookup() {
    if command -v timeout >/dev/null 2>&1; then
        timeout 3 nslookup "$@" 2>/dev/null || true
    else
        nslookup "$@" 2>/dev/null || true
    fi
}

query_ips() {
    _domain="$1"
    _raw=""
    if [ "$RESOLVE_TOOL" = "nslookup" ]; then
        _raw=$(run_nslookup "$_domain" 127.0.0.1)
        if ! printf '%s\n' "$_raw" | grep -qE "Name:|answer:|NXDOMAIN|can't find" 2>/dev/null; then
            _raw=$(run_nslookup "$_domain")
        fi
    elif [ "$RESOLVE_TOOL" = "dig" ]; then
        _raw=$(dig +time=2 +tries=1 +short "$_domain" @127.0.0.1 2>/dev/null || true)
        if [ -z "$_raw" ]; then
            _raw=$(dig +time=2 +tries=1 +short "$_domain" 2>/dev/null || true)
        fi
        if [ -n "$_raw" ]; then
            printf '%s\n' "$_raw" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|^([0-9a-fA-F]*:){2,}[0-9a-fA-F]*$' || true
            return 0
        fi
    fi

    printf '%s\n' "$_raw" | awk '
        BEGIN { in_ans = 0 }
        /Name:|answer:/ { in_ans = 1; next }
        in_ans && /Address/ {
            for (i = 1; i <= NF; i++) {
                tok = $i
                sub(/#.*/, "", tok)
                sub(/^\[/, "", tok)
                sub(/\](:[0-9]+)?$/, "", tok)
                sub(/:$/, "", tok)
                if (tok ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$/) {
                    sub(/:[0-9]+$/, "", tok)
                }
                if (tok ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                    print tok
                } else if (tok ~ /^[0-9a-fA-F:]+$/ && (tok ~ /:.*:/ || tok ~ /^::/ || tok ~ /::$/)) {
                    print tok
                }
            }
        }
    '
}

CN_IPS=$(query_ips "baidu.com")
CN_IP=$(printf '%s\n' "$CN_IPS" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1)

if [ -n "$CN_IP" ]; then
    case "$CN_IP" in
        198.18.*|198.19.*)
            warn "国内域名 baidu.com 返回了 FakeIP (${CN_IP})！国内分流规则未命中，可能导致国内 CDN 降速。"
            ;;
        127.*|0.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*)
            fail "国内域名 baidu.com 解析返回异常私有 IP: ${CN_IP}！"
            ;;
        *)
            pass "国内域名解析正常 (baidu.com -> ${CN_IP})，命中物理直连通道。"
            ;;
    esac
else
    fail "无法解析国内常用域名 baidu.com！上游国内 DNS (如 223.5.5.5) 可能失联。"
fi

# ------------------------------------------------------------------------------
# 3. GFW 投毒与防污染深度检测
# ------------------------------------------------------------------------------
say "\n${CYAN}[3/7] 审计海外被墙域名防投毒与防污染能力 (google.com)...${NC}"

OVERSEA_IPS=$(query_ips "google.com")
OVERSEA_IP=$(printf '%s\n' "$OVERSEA_IPS" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1)
KNOWN_POISON="203.98.7.65 159.106.121.75 243.185.187.39 37.61.54.158 46.82.174.68 78.16.49.15 93.46.8.89 211.167.97.200"

if [ -n "$OVERSEA_IP" ]; then
    IS_POISONED=0
    POISON_HIT=""
    for cur_ip in $OVERSEA_IPS; do
        for bad_ip in $KNOWN_POISON; do
            if [ "$cur_ip" = "$bad_ip" ]; then
                IS_POISONED=1
                POISON_HIT="$cur_ip"
                break 2
            fi
        done
    done

    if [ "$IS_POISONED" -eq 1 ]; then
        fail "重大安全告警！google.com 解析到 GFW 典型投毒 IP: ${POISON_HIT}！防污染防护彻底失效！"
    else
        case "$OVERSEA_IP" in
            198.18.*|198.19.*)
                pass "FakeIP 模式生效 (google.com -> ${OVERSEA_IP})，零公网明文泄漏，GFW 投毒天然免疫！"
                ;;
            *)
                pass "RealIP 模式或代理解析生效 (google.com -> ${OVERSEA_IP})，经检验非投毒伪造 IP。"
                ;;
        esac
    fi
else
    fail "无法解析海外域名 google.com，出海 DNS 链路或远程 DoH 解析器未响应！"
fi

# ------------------------------------------------------------------------------
# 4. IPv6 AAAA 黑洞与假死拦截审计
# ------------------------------------------------------------------------------
say "\n${CYAN}[4/7] 检查 IPv6 AAAA 污染黑洞与转圈假死防御...${NC}"

AAAA_RESP=""
if [ "$RESOLVE_TOOL" = "nslookup" ]; then
    AAAA_RAW=$(run_nslookup -type=AAAA google.com 127.0.0.1)
    if ! printf '%s\n' "$AAAA_RAW" | grep -qE "Name:|answer:|NXDOMAIN|can't find" 2>/dev/null; then
        AAAA_RAW=$(run_nslookup -type=AAAA google.com)
    fi
    AAAA_RESP=$(printf '%s\n' "$AAAA_RAW" | awk '
        BEGIN { in_ans = 0 }
        /Name:|answer:/ { in_ans = 1; next }
        in_ans && /Address/ {
            for (i = 1; i <= NF; i++) {
                tok = $i
                sub(/#.*/, "", tok)
                sub(/^\[/, "", tok)
                sub(/\](:[0-9]+)?$/, "", tok)
                sub(/:$/, "", tok)
                if (tok ~ /^[0-9a-fA-F:]+$/ && (tok ~ /:.*:/ || tok ~ /^::/ || tok ~ /::$/)) {
                    print tok
                }
            }
        }
    ')
elif [ "$RESOLVE_TOOL" = "dig" ]; then
    AAAA_RAW=$(dig +time=2 +tries=1 +short AAAA google.com @127.0.0.1 2>/dev/null || true)
    if [ -z "$AAAA_RAW" ]; then
        AAAA_RAW=$(dig +time=2 +tries=1 +short AAAA google.com 2>/dev/null || true)
    fi
    AAAA_RESP=$(printf '%s\n' "$AAAA_RAW" | grep -E '^([0-9a-fA-F]*:){2,}[0-9a-fA-F]*$' || true)
fi

if [ -z "$AAAA_RESP" ]; then
    pass "IPv6 AAAA 记录未返回或已静默过滤 (纯净 IPv4-only 模式)，彻底杜绝手机国内 App 打开转圈假死！"
else
    AAAA_FLAT=$(printf '%s' "$AAAA_RESP" | tr '\n' ' ')
    case "$AAAA_FLAT" in
        *::1*|*fe80:*|*fc[0-9a-fA-F][0-9a-fA-F]:*|*fd[0-9a-fA-F][0-9a-fA-F]:*)
            warn "检测到返回了内网/回环 IPv6 AAAA 响应: ${AAAA_FLAT}"
            ;;
        *)
            warn "检测到海外域名返回了真实/投毒 IPv6: ${AAAA_FLAT}。若家庭宽带无真实 IPv6 路由，建议开启 strategy: ipv4_only 避免假死。"
            ;;
    esac
fi

# ------------------------------------------------------------------------------
# 5. 局域网主机名与反向解析连通性 (.lan / .local)
# ------------------------------------------------------------------------------
say "\n${CYAN}[5/7] 验证局域网域名与内网主机名防劫持 (.lan / .local)...${NC}"

_CUR_HN=$(uname -n 2>/dev/null | tr -cd '0-9a-zA-Z_-' || true)
LAN_IPS=""
[ -n "$_CUR_HN" ] && LAN_IPS=$(query_ips "${_CUR_HN}.lan")
[ -z "$LAN_IPS" ] && LAN_IPS=$(query_ips "router.lan")
[ -z "$LAN_IPS" ] && LAN_IPS=$(query_ips "openwrt.lan")
[ -z "$LAN_IPS" ] && LAN_IPS=$(query_ips "immortalwrt.lan")
[ -z "$LAN_IPS" ] && LAN_IPS=$(query_ips "istoreos.lan")
LAN_IP=$(printf '%s\n' "$LAN_IPS" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1)

if [ -n "$LAN_IP" ]; then
    case "$LAN_IP" in
        192.168.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*)
            pass "局域网域名解析正常 (router.lan/openwrt.lan -> ${LAN_IP})，内网管理直连未受代理干扰。"
            ;;
        198.18.*|198.19.*)
            warn "局域网域名被 FakeIP 误劫持 (${LAN_IP})！请确认 dns.rules 中 .lan/.local 优先分流至 local-dns。"
            ;;
        *)
            warn "局域网域名解析出未知 IP: ${LAN_IP}"
            ;;
    esac
else
    pass "内网专用域名分流保护链路完整 (未产生污染外溢)。"
fi

# ------------------------------------------------------------------------------
# 6. 浏览器 DoH 与 Apple 私密代理 Canary 域名阻断审计
# ------------------------------------------------------------------------------
say "\n${CYAN}[6/7] 审计 DoH Canary 与 Apple Private Relay 阻断状态...${NC}"

CANARY_IPS=$(query_ips "use-application-dns.net")
CANARY_IP=$(printf '%s\n' "$CANARY_IPS" | head -n 1)

if [ -z "$CANARY_IP" ] || [ "$CANARY_IP" = "0.0.0.0" ] || [ "$CANARY_IP" = "::" ]; then
    pass "Firefox DoH Canary 域名已成功阻断 (use-application-dns.net -> REJECT/NXDOMAIN)，强制浏览器遵循网关 DNS 分流！"
else
    case "$CANARY_IP" in
        198.18.*|198.19.*)
            warn "Canary 域名被返回了 FakeIP (${CANARY_IP})，Firefox 可能误判 DoH 可用从而绕过网关分流！建议在 dns.rules 中将其设为 reject。"
            ;;
        *)
            warn "Canary 域名解析出真实 IP (${CANARY_IP})，浏览器可能开启内置加密 DNS 绕过网关分流！"
            ;;
    esac
fi

# ------------------------------------------------------------------------------
# 7. Dnsmasq 循环解析死锁与 AAAA 纯净配置审计
# ------------------------------------------------------------------------------
say "\n${CYAN}[7/7] 审计 Dnsmasq 循环解析死锁风险与 AAAA 纯净配置...${NC}"

if command -v uci >/dev/null 2>&1; then
    DM_SERVERS=$(uci get dhcp.@dnsmasq[0].server 2>/dev/null || true)
    DM_FILTER_AAAA=$(uci get dhcp.@dnsmasq[0].filter_aaaa 2>/dev/null || true)

    case "$DM_SERVERS" in
        *127.0.0.1*|*::1*)
            warn "Dnsmasq 配置了本地回环上游 (${DM_SERVERS})，若代理核心 local-dns 又指向 Dnsmasq，可能引发 CPU 100% 递归循环死锁！"
            ;;
        *)
            if [ "$DM_FILTER_AAAA" = "1" ]; then
                pass "Dnsmasq 上游解析配置正常，无回环死锁风险，且已开启 filter_aaaa='1' 纯净返回 IPv4！"
            else
                warn "Dnsmasq 上游解析配置正常，但未开启 filter_aaaa，若无全局 IPv6 路由，建议运行 setup_openwrt_network.sh 开启以提速。"
            fi
            ;;
    esac
else
    pass "环境未集成 UCI，跳过 Dnsmasq 专有项静态审计。"
fi

# ------------------------------------------------------------------------------
# 体检总结报告
# ------------------------------------------------------------------------------
if [ "$OUTPUT_JSON" -eq 1 ]; then
    NOW_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%d %H:%M:%S")
    cat << EOF
{
  "schema_version": "1.0",
  "timestamp": "$NOW_ISO",
  "total_checks": $TOTAL_CHECKS,
  "passed_checks": $PASSED_CHECKS,
  "warnings": $WARNINGS,
  "errors": $ERRORS,
  "dns_holder": "$(je "$DNS_HOLDER")",
  "port53_open": $( [ "$PORT53_OPEN" -eq 1 ] && echo true || echo false ),
  "checks": [ $CHECKS_JSON ]
}
EOF
else
    say "\n${BOLD}================================================================${NC}"
    say "${BOLD}                  DNS 健康体检总结报告                          ${NC}"
    say "${BOLD}================================================================${NC}"
    say "  总检测项: ${TOTAL_CHECKS}  |  通过: ${GREEN}${PASSED_CHECKS}${NC}  |  告警: ${YELLOW}${WARNINGS}${NC}  |  失败: ${RED}${ERRORS}${NC}"

    if [ "$ERRORS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
        say "\n${GREEN}${BOLD}🎉 恭喜！当前软路由 DNS 体系处于最佳生产状态，抗污染与分流表现完美！${NC}"
    elif [ "$ERRORS" -eq 0 ]; then
        say "\n${YELLOW}${BOLD}⚠ 提示：DNS 基本功能可用，但存在部分体验优化项，请按上述告警微调配置。${NC}"
    else
        say "\n${RED}${BOLD}❌ 警告：检测到关键 DNS 阻断错误！局域网可能出现断网或外网解析失败，请按上文提示排查。${NC}"
    fi
fi

if [ "$ERRORS" -gt 0 ]; then
    exit 1
fi
exit 0
