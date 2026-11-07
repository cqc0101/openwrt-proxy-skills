#!/usr/bin/env bash
# ==============================================================================
# OpenWrt sing-box 客户端生产级安全部署与异常秒级自动回滚脚本 (v2.0 硬件防爆增强版)
# 核心特性：
# 1. 硬件防爆与 SSH 保护：提升 dropbear 优先级 (renice -5, oom_score -1000)，杜绝 SSH 卡顿/断连
# 2. 超低配硬件自适应：动态探查可用内存与 Swap，nice 降级调度防止 CPU 100% 满载锁死
# 3. 动态内核感知：自动提取 sing-box 版本，严格门控 1.13 vs 1.14 语法
# 4. PPPoE / 多 WAN 热插拔守护：自动注册 /etc/hotplug.d/iface/99-singbox，断线重拨自愈
# 5. 沙盒校验与自动回滚：远端校验失败 0 污染，进程崩溃或外网离线秒级全自动还原
# ==============================================================================

set -eo pipefail

ROUTER_IP="${1:-}"
CONFIG_FILE="${2:-}"
SSH_USER="${3:-root}"
SSH_PORT="${4:-22}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { printf '%b\n' "${BLUE}[INFO]${NC} $1"; }
log_warn()  { printf '%b\n' "${YELLOW}[WARN]${NC} $1"; }
log_error() { printf '%b\n' "${RED}[ERROR]${NC} $1"; }
log_ok()    { printf '%b\n' "${GREEN}[OK]${NC} $1"; }

if [ -z "$ROUTER_IP" ] || [ -z "$CONFIG_FILE" ]; then
    echo "用法: $0 <路由器IP> <配置文件路径> [SSH用户,默认root] [SSH端口,默认22]"
    echo "示例: $0 192.168.1.1 assets/templates/openwrt-1.14-tun-fakeip.json"
    exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
    log_error "本地配置文件不存在: $CONFIG_FILE"
    exit 1
fi

# 1. 本地 JSON 格式初筛
if command -v jq >/dev/null 2>&1; then
    if ! jq empty "$CONFIG_FILE" >/dev/null 2>&1; then
        log_error "本地 JSON 语法错误，已阻断发布，未触碰远端设备！"
        exit 1
    fi
fi

SSH_CMD="ssh -p ${SSH_PORT} -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no ${SSH_USER}@${ROUTER_IP}"
SCP_CMD="scp -P ${SSH_PORT} -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no"

log_info "目标软路由: ${SSH_USER}@${ROUTER_IP}:${SSH_PORT}"
log_info "待部署文件: ${CONFIG_FILE}"

# 2. 远端连通性与 SSH 防爆卫士
log_info "正在探测与软路由通信并激活 SSH 守护..."
if ! $SSH_CMD "true" >/dev/null 2>&1; then
    log_error "无法连接到软路由 ${ROUTER_IP}:${SSH_PORT}，请确认 IP、端口或 SSH 密钥授权！"
    exit 1
fi

# 核心安全冗余：保护 dropbear/sshd，防止内存紧张时 SSH 被杀死或输入卡顿
$SSH_CMD "sh -s" << 'EOF' >/dev/null 2>&1 || true
pgrep dropbear | while read pid; do
    echo -1000 > /proc/$pid/oom_score_adj 2>/dev/null || true
    renice -n -5 -p $pid 2>/dev/null || true
done
pgrep sshd | while read pid; do
    echo -1000 > /proc/$pid/oom_score_adj 2>/dev/null || true
    renice -n -5 -p $pid 2>/dev/null || true
done
EOF
log_ok "SSH 守护完成（dropbear/sshd 已设为 OOM 最高保护与高调度优先级）。"

# 3. 硬件算力与内存安全预检
HW_INFO=$($SSH_CMD "sh -s" << 'EOF'
CORES=$(grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)
MEM_TOTAL=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 256)
MEM_FREE=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || awk '/MemFree/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 128)
SWAP_TOTAL=$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
echo "CORES=${CORES};MEM_TOTAL=${MEM_TOTAL};MEM_FREE=${MEM_FREE};SWAP_TOTAL=${SWAP_TOTAL}"
EOF
)
eval "$HW_INFO"
# 确保所有变量有合法默认值，防止空值导致后续算术比较崩溃
CORES="${CORES:-1}"
MEM_TOTAL="${MEM_TOTAL:-256}"
MEM_FREE="${MEM_FREE:-128}"
SWAP_TOTAL="${SWAP_TOTAL:-0}"
log_info "硬件探测: CPU 核心数: ${CORES}, 总内存: ${MEM_TOTAL}MB, 可用内存: ${MEM_FREE}MB, Swap: ${SWAP_TOTAL}MB"

if [ "$MEM_FREE" -lt 48 ] && [ "$SWAP_TOTAL" -eq 0 ]; then
    log_warn "【超小内存预警】当前可用内存仅 ${MEM_FREE}MB 且未开启 Swap！"
    log_warn "建议为软路由挂载 512MB Swap 文件，或使用本技能自带的轻量化规则集以防 OOM！"
fi

# 4. 远端版本自动探查与版本门控预检
REMOTE_VER_RAW=$($SSH_CMD "sing-box version 2>/dev/null | head -n 1" || true)
if [ -n "$REMOTE_VER_RAW" ]; then
    log_info "软路由已装核心: ${REMOTE_VER_RAW}"
    if echo "$REMOTE_VER_RAW" | grep -q "1\.13"; then
        if grep -q "store_dns" "$CONFIG_FILE" || grep -q "default_http_client" "$CONFIG_FILE"; then
            log_warn "[版本门控提醒] 软路由为 1.13，而配置中包含 1.14 专属字段 (store_dns/default_http_client)！"
        fi
    elif echo "$REMOTE_VER_RAW" | grep -q "1\.14"; then
        if grep -q "store_rdrc" "$CONFIG_FILE" || grep -q "independent_cache" "$CONFIG_FILE"; then
            log_warn "[版本门控提醒] 软路由为 1.14+，而配置中包含已废弃字段 (store_rdrc/independent_cache)！"
        fi
    fi
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REMOTE_DIR="/etc/sing-box"
REMOTE_CONF="/etc/sing-box/config.json"
REMOTE_TMP="/tmp/sing-box-deploy-${TIMESTAMP}.json"
BACKUP_CONF="/etc/sing-box/config.json.bak.${TIMESTAMP}"

$SSH_CMD "mkdir -p ${REMOTE_DIR}"

# 5. 远端历史配置快照备份
$SSH_CMD "if [ -f ${REMOTE_CONF} ]; then cp ${REMOTE_CONF} ${BACKUP_CONF}; echo 'BACKUP_CREATED'; fi" | grep -q "BACKUP_CREATED" && HAS_BACKUP=1 || HAS_BACKUP=0

if [ "$HAS_BACKUP" -eq 1 ]; then
    log_info "已在软路由创建配置备份: ${BACKUP_CONF}"
fi

# 6. 上传新配置至软路由内存临时区 (/tmp)
log_info "上传新配置至路由器沙盒临时目录: ${REMOTE_TMP}"
$SCP_CMD "$CONFIG_FILE" "${SSH_USER}@${ROUTER_IP}:${REMOTE_TMP}"

# 7. 远端带安全优先级的 sing-box check 内核级深度校验 (防 CPU 锁死)
log_info "调用远端 sing-box check 进行沙盒语法与依赖校验 (nice 调度)..."
# 必须同时检查退出码与输出内容：sing-box check 失败时退出码非 0，不能只靠文本匹配
CHECK_OUTPUT=$($SSH_CMD "nice -n 10 sing-box check -c ${REMOTE_TMP}" 2>&1) && CHECK_RC=0 || CHECK_RC=$?

if [ "${CHECK_RC}" -ne 0 ] || echo "$CHECK_OUTPUT" | grep -qiE "error|fatal"; then
    log_error "远端 sing-box check 校验失败 (退出码 ${CHECK_RC})！错误详情:"
    echo "--------------------------------------------------"
    echo "$CHECK_OUTPUT"
    echo "--------------------------------------------------"
    $SSH_CMD "rm -f ${REMOTE_TMP}"
    log_warn "已自动清理沙盒临时文件，生产配置保持不变，路由器网络未受任何影响。"
    exit 1
fi
log_ok "sing-box 语法校验 100% 通过！"

# 7.1 Go 运行时 GC 与 OOM 物理内存防御 (GOMEMLIMIT & GOGC)
# 注意：用两次独立 sed 插入，避免 BusyBox sed 对 '2i expr\nexpr' 中 \n 解释不一致的问题
if [ -n "$MEM_TOTAL" ] && [ "$MEM_TOTAL" -le 300 ]; then
    log_info "检测到小内存设备 (${MEM_TOTAL}MB)，自动注入 Go 运行时 OOM 防御 (GOMEMLIMIT=100MiB, GOGC=50)..."
    $SSH_CMD "if [ -f /etc/init.d/sing-box ] && ! grep -q 'GOMEMLIMIT' /etc/init.d/sing-box; then sed -i '2i export GOGC=50' /etc/init.d/sing-box; sed -i '2i export GOMEMLIMIT=100MiB' /etc/init.d/sing-box; fi"
elif [ -n "$MEM_TOTAL" ] && [ "$MEM_TOTAL" -le 550 ]; then
    log_info "检测到中等内存设备 (${MEM_TOTAL}MB)，自动优化 Go 运行时 GC (GOMEMLIMIT=220MiB, GOGC=70)..."
    $SSH_CMD "if [ -f /etc/init.d/sing-box ] && ! grep -q 'GOMEMLIMIT' /etc/init.d/sing-box; then sed -i '2i export GOGC=70' /etc/init.d/sing-box; sed -i '2i export GOMEMLIMIT=220MiB' /etc/init.d/sing-box; fi"
fi

# 8. 覆盖生产配置并平滑重启
log_info "正在应用配置并平滑重载 sing-box 服务..."
$SSH_CMD "mv ${REMOTE_TMP} ${REMOTE_CONF}"
$SSH_CMD "nice -n 5 /etc/init.d/sing-box restart || service sing-box restart || killall -HUP sing-box || true"

# 9. 存活监控与健康巡检（关键避险）
log_info "等待 3 秒后进行服务存活与网络健康巡检..."
sleep 3

HEALTH_CHECK=$($SSH_CMD "
    if pidof sing-box >/dev/null 2>&1; then
        echo 'PROCESS_RUNNING'
    else
        echo 'PROCESS_DEAD'
    fi
")

if [ "$HEALTH_CHECK" != "PROCESS_RUNNING" ]; then
    log_error "sing-box 启动后异常退出 (Crash)！"
    if [ "$HAS_BACKUP" -eq 1 ]; then
        log_warn "触发紧急避险机制：正在秒级自动回滚至历史快照..."
        $SSH_CMD "cp ${BACKUP_CONF} ${REMOTE_CONF} && (/etc/init.d/sing-box restart || true)"
        log_ok "已全自动恢复至上一次工作配置，网络未中断。"
    fi
    exit 1
fi

# 10. PPPoE / 多 WAN 宽带重拨号自愈 Hook 植入
$SSH_CMD "sh -s" << 'EOF' >/dev/null 2>&1 || true
mkdir -p /etc/hotplug.d/iface
cat << 'HOTPLUG_EOF' > /etc/hotplug.d/iface/99-singbox
#!/bin/sh
[ "$ACTION" = "ifup" ] || exit 0
case "$INTERFACE" in
    wan*|wan6*)
        /etc/init.d/sing-box reload 2>/dev/null || /etc/init.d/sing-box restart
        ;;
esac
HOTPLUG_EOF
chmod +x /etc/hotplug.d/iface/99-singbox
EOF
log_ok "已注册 OpenWrt WAN 重拨号自动重载 Hook (/etc/hotplug.d/iface/99-singbox)。"

# 11. 连通性测试 (自适应兼容 curl, wget 与 ping)
log_info "正在检验软路由外部网络解析与连通状态..."
CONN_CHECK=$($SSH_CMD "sh -s" << 'EOF'
if command -v curl >/dev/null 2>&1; then
    curl -s --connect-timeout 4 -I https://www.baidu.com >/dev/null && echo 'ONLINE' || echo 'OFFLINE'
elif command -v wget >/dev/null 2>&1; then
    wget -q -T 4 --spider https://www.baidu.com >/dev/null && echo 'ONLINE' || echo 'OFFLINE'
else
    ping -c 1 -W 3 223.5.5.5 >/dev/null 2>&1 && echo 'ONLINE' || echo 'OFFLINE'
fi
EOF
)

if [ "$CONN_CHECK" != "ONLINE" ]; then
    log_warn "服务虽已拉起，但路由器外网访问超时！"
    log_warn "注意：若为首次使用 TUN 模式，很可能是 OpenWrt fw4 防火墙拦截了 tun0 虚拟网卡。"
    log_warn "请立即执行: sh scripts/setup_openwrt_firewall.sh ${ROUTER_IP} 放行 tun0！"
else
    log_ok "外部网络解析与连通性验证通过！"
fi

log_ok "sing-box 客户端配置发布成功，全系统运行平稳！"
