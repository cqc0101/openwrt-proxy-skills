#!/bin/sh
# ==============================================================================
# OpenWrt / ImmortalWrt 防火墙自动放行 tun0 网卡脚本
# 解决开启 TUN 代理后局域网设备无法上网、网页打不开、被 fw4/fw3 拦截的问题
# 注意：本脚本运行在本地 Linux/macOS，通过 SSH 操作远端路由器
# ==============================================================================

set -e

ROUTER_IP="${1:-}"
SSH_USER="${2:-root}"
SSH_PORT="${3:-22}"
SSH_KEY="${4:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ -z "$ROUTER_IP" ]; then
    echo "使用方式: $0 <路由器IP> [SSH用户,默认root] [SSH端口,默认22] [SSH密钥路径,可选]"
    echo "示例: $0 192.168.1.1 root 22 ~/.ssh/id_ed25519"
    exit 1
fi

KEY_OPTS=""
if [ -n "$SSH_KEY" ]; then
    [ -f "$SSH_KEY" ] || { echo "指定的 SSH 密钥文件不存在: $SSH_KEY"; exit 1; }
    KEY_OPTS="-i ${SSH_KEY}"
fi
SSH_CMD="ssh ${KEY_OPTS} -p ${SSH_PORT} -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no ${SSH_USER}@${ROUTER_IP}"

printf '%b\n' "${BLUE}[INFO]${NC} 正在连接路由器 ${SSH_USER}@${ROUTER_IP}:${SSH_PORT} 检查防火墙架构..."

$SSH_CMD "sh -s" << 'EOF'
set -e

# 1. 判断防火墙版本 (fw4 or fw3)
if command -v fw4 >/dev/null 2>&1; then
    FW_VER="fw4 (nftables)"
elif command -v fw3 >/dev/null 2>&1; then
    FW_VER="fw3 (iptables)"
else
    FW_VER="unknown"
fi

echo "[REMOTE] 路由器防火墙类型: ${FW_VER}"

# 2. 定位 lan 区域 index
# 注意：使用临时文件避免管道子 shell 中 break 无法退出的 BusyBox 问题
LAN_INDEX=""
ZONE_IDX=0
while true; do
    zone_name=$(uci get "firewall.@zone[${ZONE_IDX}].name" 2>/dev/null) || break
    if [ "$zone_name" = "lan" ]; then
        LAN_INDEX="$ZONE_IDX"
        break
    fi
    ZONE_IDX=$((ZONE_IDX + 1))
done

if [ -z "$LAN_INDEX" ]; then
    echo "[REMOTE ERROR] 未在 /etc/config/firewall 中找到 lan zone！"
    exit 1
fi

echo "[REMOTE] 找到 LAN 区域索引: @zone[${LAN_INDEX}]"

# 3. 检查 tun0 是否已被加入 device
CURRENT_DEVICES=$(uci get firewall.@zone[${LAN_INDEX}].device 2>/dev/null || true)
if echo "$CURRENT_DEVICES" | grep -qw "tun0"; then
    echo "[REMOTE OK] tun0 已在 LAN 区域放行列表中，无需重复配置！"
    exit 0
fi

echo "[REMOTE] 正在将 tun0 注入 LAN 防火墙区域放行列表..."
uci add_list firewall.@zone[${LAN_INDEX}].device='tun0'
uci commit firewall

echo "[REMOTE] 正在重载防火墙规则..."
/etc/init.d/firewall reload

echo "[REMOTE OK] 防火墙配置已生效！tun0 接口转发限制已彻底解除，局域网所有客户端可正常经由代理上网。"
EOF

printf '%b\n' "${GREEN}[OK]${NC} OpenWrt 防火墙调整完毕！"
