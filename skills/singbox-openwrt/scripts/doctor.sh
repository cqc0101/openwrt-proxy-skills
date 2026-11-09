#!/bin/sh
# ==============================================================================
# OpenWrt 科学上网智能日志诊断医生 (Log Doctor & Error Pattern Analyzer)
# 纯 POSIX /bin/sh 编写，智能解析 sing-box / dae 运行日志并提供针对性解法
# 支持标准输出 (带颜色) 或机器可读 JSON 输出 (-j / --json)
# ==============================================================================
# [共享脚本] 本文件与 dae-openwrt/scripts/doctor.sh 完全一致，修改需双份同步！

OUTPUT_JSON=0
SERVICE_NAME="all"

for arg in "$@"; do
    case "$arg" in
        -j|--json)
            OUTPUT_JSON=1
            ;;
        sing-box|singbox)
            SERVICE_NAME="sing-box"
            ;;
        dae|daed)
            SERVICE_NAME="dae"
            ;;
        all)
            SERVICE_NAME="all"
            ;;
        *)
            [ "$SERVICE_NAME" = "all" ] && SERVICE_NAME="$arg"
            ;;
    esac
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

# 1. 进程存活与端口网卡探测
SINGBOX_RUNNING=0
DAE_RUNNING=0
TUN_EXISTS=0
PORT53_OPEN=0

if pidof sing-box >/dev/null 2>&1 || pgrep -x "sing-box" >/dev/null 2>&1; then
    SINGBOX_RUNNING=1
fi

if pidof daed >/dev/null 2>&1 || pidof dae >/dev/null 2>&1 || pgrep -x "daed" >/dev/null 2>&1 || pgrep -x "dae" >/dev/null 2>&1; then
    DAE_RUNNING=1
fi

if ip link show tun0 >/dev/null 2>&1; then
    TUN_EXISTS=1
fi

if command -v netstat >/dev/null 2>&1 && netstat -tuln 2>/dev/null | grep -qE ":53[[:space:]]"; then
    PORT53_OPEN=1
elif command -v ss >/dev/null 2>&1 && ss -tuln 2>/dev/null | grep -qE ":53[[:space:]]"; then
    PORT53_OPEN=1
fi

FW_TUN_OK=0
if command -v uci >/dev/null 2>&1 && uci show firewall 2>/dev/null | grep -q "tun0"; then
    FW_TUN_OK=1
fi

OUTBOUND_OK=0
if command -v curl >/dev/null 2>&1; then
    _hc=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 -m 5 http://cp.cloudflare.com/generate_204 2>/dev/null || true)
    [ "$_hc" = "204" ] && OUTBOUND_OK=1
elif command -v wget >/dev/null 2>&1; then
    wget -q -T 3 --spider http://cp.cloudflare.com/generate_204 2>/dev/null && OUTBOUND_OK=1
fi

# 2. 收集最近运行日志
RAW_LOGS=""
if [ "$SERVICE_NAME" = "dae" ]; then
    RAW_LOGS=$(logread -e "dae" 2>/dev/null | tail -n 80)
    [ -z "$RAW_LOGS" ] && RAW_LOGS=$(logread 2>/dev/null | grep -i "dae" | tail -n 80)
    [ -z "$RAW_LOGS" ] && [ -f /var/log/dae.log ] && RAW_LOGS=$(tail -n 80 /var/log/dae.log 2>/dev/null)
elif [ "$SERVICE_NAME" = "sing-box" ]; then
    RAW_LOGS=$(logread -e "sing-box" 2>/dev/null | tail -n 80)
    [ -z "$RAW_LOGS" ] && RAW_LOGS=$(logread 2>/dev/null | grep -i "sing-box" | tail -n 80)
    [ -z "$RAW_LOGS" ] && [ -f /var/log/sing-box.log ] && RAW_LOGS=$(tail -n 80 /var/log/sing-box.log 2>/dev/null)
else
    RAW_LOGS=$(logread 2>/dev/null | grep -iE "sing-box|dae|daed" | tail -n 80)
    if [ -z "$RAW_LOGS" ]; then
        [ -f /var/log/sing-box.log ] && RAW_LOGS=$(tail -n 80 /var/log/sing-box.log 2>/dev/null)
        [ -f /var/log/dae.log ] && RAW_LOGS=$(tail -n 80 /var/log/dae.log 2>/dev/null)
    fi
fi

# 3. 故障特征检测
ISSUES_JSON=""
SUGGESTIONS_JSON=""
ISSUE_COUNT=0
OVERALL_SEVERITY="healthy"
OVERALL_CODE=0

add_issue() {
    i_id="$1"
    i_sev="$2"
    i_title="$3"
    i_desc="$4"
    i_action="$5"

    ISSUE_COUNT=$((ISSUE_COUNT + 1))
    if [ "$i_sev" = "error" ]; then
        OVERALL_SEVERITY="error"
        OVERALL_CODE=2
    elif [ "$i_sev" = "warning" ] && [ "$OVERALL_SEVERITY" != "error" ]; then
        OVERALL_SEVERITY="warning"
        [ "$OVERALL_CODE" -eq 0 ] && OVERALL_CODE=1
    fi

    item="{\"id\":\"$(je "$i_id")\",\"severity\":\"$(je "$i_sev")\",\"title\":\"$(je "$i_title")\",\"description\":\"$(je "$i_desc")\",\"action\":\"$(je "$i_action")\"}"
    if [ -z "$ISSUES_JSON" ]; then
        ISSUES_JSON="$item"
    else
        ISSUES_JSON="$ISSUES_JSON,$item"
    fi

    act_item="\"$(je "$i_action")\""
    if [ -z "$SUGGESTIONS_JSON" ]; then
        SUGGESTIONS_JSON="$act_item"
    else
        SUGGESTIONS_JSON="$SUGGESTIONS_JSON,$act_item"
    fi

    if [ "$OUTPUT_JSON" -eq 0 ]; then
        if [ "$i_sev" = "error" ]; then
            say "  ${RED}【$i_title】${NC}"
        else
            say "  ${YELLOW}【$i_title】${NC}"
        fi
        say "    - 现象: $i_desc"
        say "    - ${GREEN}一键解法${NC}: $i_action"
    fi
}

say "${BOLD}================================================================${NC}"
say "${BOLD}       OpenWrt 科学上网智能日志诊断医生 (Smart Log Doctor)       ${NC}"
say "${BOLD}================================================================${NC}"

    if pidof daed >/dev/null 2>&1 || pgrep -x daed >/dev/null 2>&1 || [ -f /etc/daed/wing.db ]; then
        add_issue "daed_conflict" "error" "检测到正在运行 Web 面板版 daed (与原生 dae 互斥)" "原生 dae 配置文件 (/etc/dae/config.dae) 会被 Web 版 daed 忽略，两者同时启动将发生 eBPF 钩子争抢" "/etc/init.d/daed stop && /etc/init.d/daed disable && /etc/init.d/dae enable && /etc/init.d/dae start"
    fi

# 进程与接口状态检测 (兼容显式指定 sing-box / dae 与默认 all 自动识别模式)
if [ "$SERVICE_NAME" = "sing-box" ]; then
    if [ "$SINGBOX_RUNNING" -eq 0 ]; then
        add_issue "service_stopped" "error" "sing-box 进程未运行" "sing-box 服务处于停止或异常退出状态" "uci set sing-box.main.enabled='1' 2>/dev/null; uci set sing-box.main.user='root' 2>/dev/null; uci commit sing-box 2>/dev/null; /etc/init.d/sing-box restart"
    fi
    if [ "$TUN_EXISTS" -eq 0 ]; then
        add_issue "tun_missing" "warning" "tun0 虚拟网卡未就绪" "系统未检测到 tun0 网卡接口，流量无法通过 TUN 转发" "sh /etc/sing-box/setup_openwrt_network.sh"
    elif command -v uci >/dev/null 2>&1 && [ "$FW_TUN_OK" -eq 0 ]; then
        add_issue "fw_tun_untrusted" "warning" "防火墙未放行 tun0 接口" "uci firewall 中未找到 tun0，局域网设备转发流量将被默认丢弃" "sh /etc/sing-box/setup_openwrt_network.sh"
    fi
elif [ "$SERVICE_NAME" = "dae" ]; then
    if [ "$DAE_RUNNING" -eq 0 ]; then
        DAE_INIT_CMD="/etc/init.d/dae restart"
        [ -x /etc/init.d/daed ] && [ ! -x /etc/init.d/dae ] && DAE_INIT_CMD="/etc/init.d/daed restart"
        add_issue "service_stopped" "error" "dae 进程未运行" "dae / daed 服务处于停止状态" "$DAE_INIT_CMD"
    fi
else
    if [ "$SINGBOX_RUNNING" -eq 0 ] && [ "$DAE_RUNNING" -eq 0 ]; then
        if [ -x /etc/init.d/dae ] || [ -f /etc/dae/config.dae ]; then
            add_issue "service_stopped" "error" "代理核心进程未运行" "未检测到运行中的 sing-box 或 dae 进程" "/etc/init.d/dae restart"
        else
            add_issue "service_stopped" "error" "代理核心进程未运行" "未检测到运行中的 sing-box 或 dae 进程" "uci set sing-box.main.enabled='1' 2>/dev/null; uci set sing-box.main.user='root' 2>/dev/null; uci commit sing-box 2>/dev/null; /etc/init.d/sing-box restart"
        fi
    fi
    if [ "$SINGBOX_RUNNING" -eq 1 ]; then
        if [ "$TUN_EXISTS" -eq 0 ]; then
            add_issue "tun_missing" "warning" "tun0 虚拟网卡未就绪" "系统未检测到 tun0 网卡接口，流量无法通过 TUN 转发" "sh /etc/sing-box/setup_openwrt_network.sh"
        elif command -v uci >/dev/null 2>&1 && [ "$FW_TUN_OK" -eq 0 ]; then
            add_issue "fw_tun_untrusted" "warning" "防火墙未放行 tun0 接口" "uci firewall 中未找到 tun0，局域网设备转发流量将被默认丢弃" "sh /etc/sing-box/setup_openwrt_network.sh"
        fi
    fi
fi

# 日志模式扫描
if [ -n "$RAW_LOGS" ]; then
    # 特征 1: 时钟偏差与 TLS 证书报错
    if echo "$RAW_LOGS" | grep -qiE "certificate|x509|expired|validity"; then
        add_issue "tls_clock_skew" "error" "TLS 证书与时间同步异常" "系统时钟未对齐 (如停留在 1970 年)，导致 TLS 握手被拒" "ntpd -q -p ntp.aliyun.com"
    fi

    # 特征 2: 上游 DNS 递归死锁或解析超时（严禁将 Dnsmasq server 指向未监听的 本地死端口 避免全网断网）
    if echo "$RAW_LOGS" | grep -qiE "temporary failure in name resolution|lookup .* i/o timeout|server failure"; then
        add_issue "dns_lookup_timeout" "error" "DNS 解析超时与自环死锁风险" "无法解析节点 VPS 域名或规则集，可能上游 DNS 递归死锁" "uci delete dhcp.@dnsmasq[0].server 2>/dev/null; uci commit dhcp && /etc/init.d/dnsmasq restart"
    fi

    # 特征 3: 规则集下载被阻断 (冷启动死锁)
    if echo "$RAW_LOGS" | grep -qiE "download rule-set.*(error|fail|timeout|deadline)|rule.?set.*(download|fetch|error|timeout|deadline|failed|context deadline exceeded)|(raw\.githubusercontent\.com|githubusercontent\.com).*(error|fail|timeout|deadline|refused|reset)"; then
        add_issue "ruleset_download_blocked" "error" "规则集下载被 GFW 阻断 (冷启动死锁)" "sing-box 启动时拉取 remote .srs 超时导致服务卡死" "重新生成配置并指定国内 CDN 镜像加速 (--mirror jsdelivr)，切勿显式配置 download_detour: direct (启动必崩)"
    fi

    # 特征 4: 端口冲突
    if echo "$RAW_LOGS" | grep -qiE "bind: address already in use"; then
        add_issue "port_conflict" "error" "监听端口冲突" "53/9090 端口已被其他服务 (PassWall/OpenClash/AdGuardHome) 占用" "netstat -tulnp | grep -E ':(53|9090)' 查杀冲突进程"
    fi

    # 特征 5: OOM 物理内存耗尽
    if echo "$RAW_LOGS" | grep -qiE "out of memory|killed process|fatal error: runtime: out of memory"; then
        add_issue "oom_killed" "error" "硬件 OOM 内存溢出崩机" "路由器物理 RAM 耗尽被 Linux 内核 OOM Killer 强行终止" "配置 512MB swapfile 并注入 export GOMEMLIMIT=100MiB"
    fi

    # 特征 6: dae eBPF 加载异常
    if echo "$RAW_LOGS" | grep -qiE "failed to load ebpf|bpf_prog_load|btf.*(not found|mismatch|missing)|no btf"; then
        add_issue "ebpf_btf_missing" "error" "dae eBPF 加载失败 (缺失 BTF 符号)" "OpenWrt 内核缺少 BTF 调试符号支持" "安装 vmlinux-btf 内核包，或改用 singbox-openwrt (TUN 模式)"
    fi

    # 特征 7: 配置解析语法错误
    if echo "$RAW_LOGS" | grep -qiE "decode config|parse config|unmarshal.*error|invalid json|configuration file .* error"; then
        add_issue "config_syntax_error" "error" "配置文件语法/格式错误" "配置文件 JSON 格式损坏或包含未识别字段" "sing-box check -c /etc/sing-box/config.json"
    fi

    # 特征 8: auto_redirect 与 nfqueue 内核缺损自环
    if echo "$RAW_LOGS" | grep -qiE "nfqueue start failed|missing nfnetlink_queue"; then
        add_issue "nfqueue_missing_loop" "error" "auto_redirect 导致内核流量自环" "内核缺少 nfqueue 模块，auto_redirect 回退为端口重定向导致流量自捕获" "sed -i 's/\"auto_redirect\": true/\"auto_redirect\": false/g' /etc/sing-box/config.json && /etc/init.d/sing-box restart"
    fi

    # 特征 9: 节点认证或 Reality 验签失败
    if echo "$RAW_LOGS" | grep -qiE "reality verification failed|authentication failed.*404"; then
        add_issue "node_auth_failed" "error" "出海节点认证或 Reality 验签失败" "节点 UUID、Short ID 或密码与服务端不一致，流量被阻断" "检查节点链接参数或刷新机场订阅并重新生成配置"
    fi
fi

if [ "$OUTPUT_JSON" -eq 1 ]; then
    NOW_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%d %H:%M:%S")
    LOG_TAIL_RAW=$(printf '%s\n' "$RAW_LOGS" | tail -n 20)
    LOG_TAIL_JSON=$(je "$LOG_TAIL_RAW")
    cat << EOF
{
  "service": "$(je "$SERVICE_NAME")",
  "status": "$OVERALL_SEVERITY",
  "overall_code": $OVERALL_CODE,
  "timestamp": "$NOW_ISO",
  "singbox_running": $( [ "$SINGBOX_RUNNING" -eq 1 ] && echo true || echo false ),
  "dae_running": $( [ "$DAE_RUNNING" -eq 1 ] && echo true || echo false ),
  "tun_alive": $( [ "$TUN_EXISTS" -eq 1 ] && echo true || echo false ),
  "fw_tun_ok": $( [ "$FW_TUN_OK" -eq 1 ] && echo true || echo false ),
  "port53_open": $( [ "$PORT53_OPEN" -eq 1 ] && echo true || echo false ),
  "outbound_ok": $( [ "$OUTBOUND_OK" -eq 1 ] && echo true || echo false ),
  "issue_count": $ISSUE_COUNT,
  "issues": [ $ISSUES_JSON ],
  "suggested_actions": [ $SUGGESTIONS_JSON ],
  "recent_logs": "$LOG_TAIL_JSON"
}
EOF
else
    if [ -n "$RAW_LOGS" ]; then
        say "${CYAN}[1/2] 最近运行日志摘录 (最近 15 行):${NC}"
        echo "$RAW_LOGS" | tail -n 15
        echo ""
    else
        say "  ${YELLOW}[!] 未在系统 logread 中检索到相关运行日志 (服务可能未启动或刚重启)。${NC}"
    fi

    say "${CYAN}[2/2] 智能故障特征深度分析:${NC}"
    if [ "$ISSUE_COUNT" -eq 0 ]; then
        say "  ${GREEN}[✓] 未发现已知典型严重报错，服务整体运行平稳。${NC}"
    else
        say "  ${YELLOW}[!] 共检测到 $ISSUE_COUNT 个潜在异常/错误，请执行上方建议的修复指令。${NC}"
    fi
    say "${BOLD}================================================================${NC}"
fi

exit $OVERALL_CODE
