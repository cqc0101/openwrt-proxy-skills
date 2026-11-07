#!/bin/sh
# ==============================================================================
# OpenWrt / ImmortalWrt / iStoreOS 系统级网络性能调优脚本 (Performance Tuning)
# 纯 POSIX /bin/sh 编写，写入独立配置文件 /etc/sysctl.d/99-proxy-tuning.conf
# ==============================================================================
# [共享脚本] 本文件与 dae-openwrt/scripts/optimize_network.sh 完全一致，修改需双份同步！

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo "${BOLD}================================================================${NC}"
echo "${BOLD}         OpenWrt 系统级网络性能与 BBR 自动调优工具              ${NC}"
echo "${BOLD}================================================================${NC}"

CONF_DIR="/etc/sysctl.d"
# 始终使用独立配置文件；严禁直接覆盖 /etc/sysctl.conf（会清空用户既有调优）
mkdir -p "$CONF_DIR" 2>/dev/null || CONF_DIR="/etc"
CONF_FILE="$CONF_DIR/99-proxy-tuning.conf"
# 若目标文件已存在且非本脚本生成，先备份，避免覆盖用户配置
if [ -f "$CONF_FILE" ] && ! grep -q "OpenWrt 科学上网高并发与网络连接池优化参数" "$CONF_FILE" 2>/dev/null; then
    cp "$CONF_FILE" "$CONF_FILE.bak.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
fi

echo "${BLUE}[1/4] 开启内核 IPv4 数据包转发 (net.ipv4.ip_forward=1)...${NC}"
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

echo "${BLUE}[2/4] 探测并配置 BBR 拥塞控制算法与队列规则...${NC}"
HAS_BBR=0
if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw "bbr"; then
    HAS_BBR=1
elif lsmod 2>/dev/null | grep -qw "tcp_bbr"; then
    HAS_BBR=1
elif modprobe tcp_bbr 2>/dev/null; then
    HAS_BBR=1
fi

# 注意：BBR_CONF 变量分两行存储，避免 \n 在不同 shell 实现下的歧义
if [ "$HAS_BBR" -eq 1 ]; then
    echo "  ${GREEN}[✓] 内核支持 BBR！正在激活 BBR + fq_codel 算法...${NC}"
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1
    sysctl -w net.core.default_qdisc=fq_codel >/dev/null 2>&1 || sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1
    BBR_LINE1="net.ipv4.tcp_congestion_control = bbr"
    BBR_LINE2="net.core.default_qdisc = fq_codel"
else
    echo "  ${YELLOW}[!] 当前内核未编译 BBR 模块，保持当前拥塞算法 ($(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)).${NC}"
    BBR_LINE1="# net.ipv4.tcp_congestion_control = bbr (内核未开启)"
    BBR_LINE2=""
fi

echo "${BLUE}[3/4] 优化高并发连接池与 TCP 超时保活参数...${NC}"
# 写入独立持久化配置文件（不存在用户配置被覆盖的风险）
mkdir -p "$CONF_DIR" 2>/dev/null || true
cat > "$CONF_FILE" << EOF
# ==============================================================================
# OpenWrt 科学上网高并发与网络连接池优化参数
# ==============================================================================
net.ipv4.ip_forward = 1

# BBR 拥塞控制
${BBR_LINE1}
${BBR_LINE2}

# 连接池与高并发调优
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fastopen = 3

# 连接跟踪上限 (防止满载丢包；net.netfilter 路径兼容新内核)
net.netfilter.nf_conntrack_max = 65536
EOF

echo "${BLUE}[4/4] 正在加载并应用调优参数 (sysctl -p)...${NC}"
# 使用 || true 忽略个别内核不支持的参数（如 nf_conntrack 未加载时）
sysctl -p "$CONF_FILE" >/dev/null 2>&1 || true

echo ""
echo "${GREEN}${BOLD}【调优完成】系统级网络参数已生效并持久化至 ${CONF_FILE}！${NC}"
echo "  - IPv4 转发 : $(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
echo "  - 拥塞控制  : $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
echo "  - 最大连接数: $(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || sysctl -n net.nf_conntrack_max 2>/dev/null || echo 'N/A (conntrack 模块未加载)')"
echo "${BOLD}================================================================${NC}"
