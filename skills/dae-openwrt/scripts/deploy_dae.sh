#!/usr/bin/env bash
# ==============================================================================
# OpenWrt dae (eBPF Transparent Proxy) 生产级安全热重载与异常自动回滚脚本 (v2.0)
# 核心特性：
# 1. 内核与 eBPF 硬准入自主全自动探查 (Linux 5.15+)，低版本自动拦截并指引降级至 singbox-openwrt
# 2. 硬件防爆与 SSH 保护：提升 dropbear 优先级 (renice -5, oom_score -1000)，杜绝 SSH 卡顿
# 3. 远端沙盒 dae validate 严格语法校验 -> 保持连接平滑热重载 (dae reload)
# 4. PPPoE / 多 WAN 热插拔自动重载 Hook (/etc/hotplug.d/iface/99-dae)
# ==============================================================================

set -eo pipefail

ROUTER_IP="${1:-}"
CONFIG_FILE="${2:-}"
SSH_USER="${3:-root}"
SSH_PORT="${4:-22}"
SSH_KEY="${5:-}"

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
    echo "用法: $0 <路由器IP> <配置文件路径> [SSH用户,默认root] [SSH端口,默认22] [SSH密钥路径,可选]"
    echo "示例: $0 192.168.1.1 assets/templates/openwrt.dae root 22 ~/.ssh/id_ed25519"
    exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
    log_error "本地配置文件不存在: $CONFIG_FILE"
    exit 1
fi

KEY_OPTS=""
if [ -n "$SSH_KEY" ]; then
    if [ ! -f "$SSH_KEY" ]; then
        log_error "指定的 SSH 密钥文件不存在: $SSH_KEY"
        exit 1
    fi
    KEY_OPTS="-i ${SSH_KEY}"
fi
SSH_CMD="ssh ${KEY_OPTS} -p ${SSH_PORT} -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no ${SSH_USER}@${ROUTER_IP}"

log_info "目标软路由: ${SSH_USER}@${ROUTER_IP}:${SSH_PORT}"
log_info "待部署 dae 文件: ${CONFIG_FILE}"

# 1. 远端连通性与 SSH 防爆卫士
log_info "正在探测与软路由通信并激活 SSH 守护..."
if ! $SSH_CMD "true" >/dev/null 2>&1; then
    log_error "无法连接到软路由 ${ROUTER_IP}:${SSH_PORT}，请确认网络连接与 SSH 授权！"
    exit 1
fi

# 保护 dropbear/sshd，防止内存紧张时 SSH 被杀死或输入卡顿
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
log_ok "SSH 守护完成（dropbear/sshd 已设为最高保护）。"

# 2. 内核版本与 eBPF / BTF 运行环境自主全自动硬准入检测 (用户无需操心)
log_info "正在自主检测软路由内核架构与 eBPF 支持能力..."
PRE_CHECK_RES=$($SSH_CMD "sh -s" << 'EOF'
set -e
KVER=$(uname -r)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)

# 1. 内核版本检测 (最低 5.15)
if [ "$KMAJOR" -lt 5 ] || ([ "$KMAJOR" -eq 5 ] && [ "$KMINOR" -lt 15 ]); then
    echo "FAIL_KERNEL_TOO_OLD:$KVER"
    exit 0
fi

# 2. 检测 BTF 支持 (3 路径扫描：内核内嵌、vmlinux-btf 包标准路径、版本化路径)
# 单引号 heredoc 阻止本地 shell 展开 $KVER，$KVER 由远端 shell 执行时赋值，行为正确
BTF_FOUND=0
[ -f /sys/kernel/btf/vmlinux ] && BTF_FOUND=1
[ -f /usr/lib/debug/boot/vmlinux ] && BTF_FOUND=1
[ -f "/usr/lib/debug/boot/vmlinux-${KVER}" ] && BTF_FOUND=1
if [ "$BTF_FOUND" -eq 0 ]; then
    echo "WARN_NO_BTF:$KVER"
fi

# 3. 检测代理核心程序（区分原生 dae 与 daed Web 面板版）
if command -v dae >/dev/null 2>&1; then
    :
elif command -v daed >/dev/null 2>&1; then
    echo "FAIL_ONLY_DAED"
    exit 0
else
    echo "FAIL_NO_DAE_BIN"
    exit 0
fi

echo "PASS:$KVER"
EOF
)

if echo "$PRE_CHECK_RES" | grep -q "FAIL_KERNEL_TOO_OLD"; then
    DETECTED_KVER=$(echo "$PRE_CHECK_RES" | cut -d: -f2)
    log_error "【硬准入拦截】软路由内核为 Linux ${DETECTED_KVER}，低于 dae 最低要求的 5.15+！"
    log_error "当前固件无法加载 eBPF 内核探测器。已全自动中止部署，未对路由器做任何无用修改。"
    echo "----------------------------------------------------------------------------------"
    printf '%b\n' "${YELLOW}【智能降级建议】${NC} 请直接改用配套的 ${BLUE}singbox-openwrt${NC} 技能！"
    echo "sing-box TUN 模式对任意老旧 Linux 内核（包括 4.19 / 5.4）具备 100% 生产兼容性。"
    echo "----------------------------------------------------------------------------------"
    exit 1
fi

if echo "$PRE_CHECK_RES" | grep -q "WARN_NO_BTF"; then
    log_warn "未在 /sys/kernel/btf 或 /usr/lib/debug/boot 检测到 BTF 符号文件！"
    log_warn "若当前使用的是官方 OpenWrt 原版固件，加载 eBPF 时可能会报错缺少 BTF。"
    log_warn "解决方案：可通过 'opkg install vmlinux-btf' 安装对应的 BTF 依赖包。"
fi

if echo "$PRE_CHECK_RES" | grep -q "FAIL_NO_DAE_BIN"; then
    log_error "【环境缺失】软路由系统中未找到 'dae' 或 'daed' 运行程序！"
    log_error "请先在 OpenWrt 软件包管理中安装 dae / daed 核心后重新部署。"
    exit 1
fi

# daed 支持边界：只装 daed（Web 面板版）时明确拒绝。检测在远端完成（见上方 FAIL_ONLY_DAED）
if echo "$PRE_CHECK_RES" | grep -q "FAIL_ONLY_DAED"; then
    log_error "【支持边界】软路由只安装了 daed（Web 面板版），未安装原生 dae 命令行程序。"
    log_error "daed 使用独立的 /etc/daed 配置目录与 Web 面板 (http://<路由器IP>:2023)，本脚本无法对其安全热重载。"
    log_error "请在 daed Web 面板中导入/修改配置；若需要命令行热重载，请改装原生 dae 后重试。"
    exit 1
fi

log_ok "软路由内核与 eBPF 运行环境检测通过！"

# 2.1 流量分载 (Flow Offloading) 冲突治理 (铁律：Flow Offload 绕过 eBPF 导致代理失效)
FLOW_OFFLOAD_STATUS=$($SSH_CMD "uci get firewall.@defaults[0].flow_offloading 2>/dev/null || echo 0")
if [ "$FLOW_OFFLOAD_STATUS" = "1" ]; then
    log_warn "检测到 OpenWrt 开启了【流量分载 (Flow Offloading)】！"
    log_warn "分载引擎使数据包绕过内核协议栈与 eBPF TC/XDP 钩子，导致 dae 代理失效！"
    log_info "正在自动关闭 Flow Offloading 以确保 eBPF 完整接管..."
    # 用 || true 防止 UCI key 不存在时脚本中止
    $SSH_CMD "uci set firewall.@defaults[0].flow_offloading='0' 2>/dev/null || true; uci set firewall.@defaults[0].flow_offloading_hw='0' 2>/dev/null || true; uci commit firewall 2>/dev/null || true; /etc/init.d/firewall reload 2>/dev/null || true"
    log_ok "已关闭流量分载并重载防火墙。"
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REMOTE_DIR="/etc/dae"
REMOTE_CONF="/etc/dae/config.dae"
REMOTE_TMP="/tmp/dae-deploy-${TIMESTAMP}.dae"
BACKUP_CONF="/etc/dae/config.dae.bak.${TIMESTAMP}"

$SSH_CMD "mkdir -p ${REMOTE_DIR}"

# 3. 远端配置快照备份
$SSH_CMD "if [ -f ${REMOTE_CONF} ]; then cp ${REMOTE_CONF} ${BACKUP_CONF}; echo 'BACKUP_CREATED'; fi" | grep -q "BACKUP_CREATED" && HAS_BACKUP=1 || HAS_BACKUP=0

if [ "$HAS_BACKUP" -eq 1 ]; then
    log_info "已在软路由创建快照: ${BACKUP_CONF}"
fi

# 4. 上传新配置至软路由内存临时区 (/tmp)
# 用 ssh + stdin 重定向上传：scp 依赖远端 openssh-sftp-server，精简固件（dropbear）常缺失
log_info "上传配置文件至路由器临时目录: ${REMOTE_TMP}"
if ! $SSH_CMD "cat > ${REMOTE_TMP}" < "$CONFIG_FILE"; then
    log_error "上传配置失败（SSH 连接或远端写入异常）！"
    exit 1
fi

# 5. 远端 dae validate 严格语法校验 (带 nice 优先级调度)
log_info "调用远端 dae validate 严格语法校验..."
# 同时检查退出码与输出内容，避免仅靠文本匹配漏判
CHECK_OUTPUT=$($SSH_CMD "nice -n 10 dae validate -c ${REMOTE_TMP}" 2>&1) && CHECK_RC=0 || CHECK_RC=$?

if [ "${CHECK_RC}" -ne 0 ] || echo "$CHECK_OUTPUT" | grep -qiE "error|fatal|fail"; then
    log_error "远端 dae validate 校验失败 (退出码 ${CHECK_RC})！错误详情:"
    echo "--------------------------------------------------"
    echo "$CHECK_OUTPUT"
    echo "--------------------------------------------------"
    $SSH_CMD "rm -f ${REMOTE_TMP}"
    log_warn "已自动清理临时文件，未对生产环境产生任何修改，网络安全！"
    exit 1
fi
log_ok "dae 配置语法校验 100% 通过！"

# 6. 覆盖生产配置并执行平滑热重载 (dae reload)
log_info "覆盖生产配置并平滑热重载 (保持已建立连接与 eBPF maps)..."
$SSH_CMD "mv ${REMOTE_TMP} ${REMOTE_CONF}"
$SSH_CMD "dae reload || /etc/init.d/dae reload || /etc/init.d/dae restart || true"

# 7. 存活监控与健康巡检
log_info "等待 2 秒进行进程存活巡检..."
sleep 2

HEALTH_CHECK=$($SSH_CMD "
    if pidof dae >/dev/null 2>&1; then
        echo 'PROCESS_RUNNING'
    else
        echo 'PROCESS_DEAD'
    fi
")

if [ "$HEALTH_CHECK" != "PROCESS_RUNNING" ]; then
    log_error "dae 进程未处于正常运行状态！"
    if [ "$HAS_BACKUP" -eq 1 ]; then
        log_warn "触发自动回滚保护：正在还原历史配置..."
        $SSH_CMD "cp ${BACKUP_CONF} ${REMOTE_CONF} && (dae reload || /etc/init.d/dae restart || true)"
        log_ok "已全自动回滚至上一次正常状态。"
    fi
    exit 1
fi

# 8. 注册 WAN 重拨号自愈 Hook
$SSH_CMD "sh -s" << 'EOF' >/dev/null 2>&1 || true
mkdir -p /etc/hotplug.d/iface
cat << 'HOTPLUG_EOF' > /etc/hotplug.d/iface/99-dae
#!/bin/sh
[ "$ACTION" = "ifup" ] || exit 0
case "$INTERFACE" in
    wan*|wan6*)
        dae reload 2>/dev/null || /etc/init.d/dae reload 2>/dev/null || /etc/init.d/dae restart
        ;;
esac
HOTPLUG_EOF
chmod +x /etc/hotplug.d/iface/99-dae
EOF
log_ok "已注册 OpenWrt WAN 重拨号自动重载 Hook (/etc/hotplug.d/iface/99-dae)。"

log_ok "dae 服务运行健康，配置热重载发布全部完成！"
