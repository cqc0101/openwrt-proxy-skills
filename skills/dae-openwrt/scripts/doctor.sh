#!/bin/sh
# ==============================================================================
# OpenWrt 科学上网智能日志诊断医生 (Log Doctor & Error Pattern Analyzer)
# 纯 POSIX /bin/sh 编写，智能解析 sing-box / dae 运行日志并提供针对性解法
# ==============================================================================
# [共享脚本] 本文件与 singbox-openwrt/scripts/doctor.sh 完全一致，修改需双份同步！

SERVICE_NAME="${1:-all}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo "${BOLD}================================================================${NC}"
echo "${BOLD}       OpenWrt 科学上网智能日志诊断医生 (Smart Log Doctor)       ${NC}"
echo "${BOLD}================================================================${NC}"

RAW_LOGS=""
if [ "$SERVICE_NAME" = "dae" ]; then
    # logread -e 在标准 OpenWrt logread 中支持，加 2>/dev/null 兜底
    RAW_LOGS=$(logread -e "dae" 2>/dev/null | tail -n 80)
    [ -z "$RAW_LOGS" ] && RAW_LOGS=$(logread 2>/dev/null | grep -i "dae" | tail -n 80)
elif [ "$SERVICE_NAME" = "sing-box" ]; then
    RAW_LOGS=$(logread -e "sing-box" 2>/dev/null | tail -n 80)
    [ -z "$RAW_LOGS" ] && RAW_LOGS=$(logread 2>/dev/null | grep -i "sing-box" | tail -n 80)
else
    RAW_LOGS=$(logread 2>/dev/null | grep -iE "sing-box|dae|daed" | tail -n 80)
fi

if [ -z "$RAW_LOGS" ]; then
    # 尝试读取 /var/log/
    if [ -f /var/log/sing-box.log ]; then
        RAW_LOGS=$(tail -n 80 /var/log/sing-box.log)
    elif [ -f /var/log/dae.log ]; then
        RAW_LOGS=$(tail -n 80 /var/log/dae.log)
    fi
fi

if [ -z "$RAW_LOGS" ]; then
    echo "  ${YELLOW}[!] 未在系统 logread 中检索到 sing-box 或 dae 的相关运行日志。${NC}"
    echo "  ${BLUE}[i] 服务可能刚刚重启，或尚未产生日志输出。${NC}"
    echo "${BOLD}================================================================${NC}"
    exit 0
fi

echo "${CYAN}[1/2] 最近运行日志摘录 (最近 15 行):${NC}"
echo "$RAW_LOGS" | tail -n 15
echo ""

echo "${CYAN}[2/2] 智能故障特征深度分析:${NC}"
MATCHED=0

# 特征 1: 时钟偏差与 TLS 证书报错
if echo "$RAW_LOGS" | grep -qiE "certificate|x509|expired|validity"; then
    MATCHED=1
    echo "  ${RED}【发现 TLS 证书/时间同步异常】${NC}"
    echo "    - 现象: 日志中出现 certificate has expired 或 x509 校验失败。"
    echo "    - 原因: 软路由断电开机后系统时钟未对齐 (如停留在 1970 或 2023 年)，导致 TLS 握手被拒。"
    echo "    - ${GREEN}一键解法${NC}: 运行 'ntpd -q -p ntp.aliyun.com' 立即强制同步互联网时间！"
fi

# 特征 2: 上游 DNS 递归死锁或解析超时
if echo "$RAW_LOGS" | grep -qiE "temporary failure in name resolution|lookup .* i/o timeout|server failure"; then
    MATCHED=1
    echo "  ${RED}【发现 DNS 解析超时与死循环风险】${NC}"
    echo "    - 现象: 出现 DNS lookup timeout，无法解析节点 VPS 域名或规则集。"
    echo "    - 原因: default_domain_resolver 未指定可信国内直连 DNS，或陷入 DNS 自环。"
    echo "    - ${GREEN}一键解法${NC}: 确保 route.default_domain_resolver 指向 'alidns' (223.5.5.5)。"
fi

# 特征 3: 规则集下载超时 (被 GFW 阻断)
# 注意：不要匹配孤立的 connection refused/reset，那会大面积误诊
if echo "$RAW_LOGS" | grep -qiE "download rule-set|rule.?set.*(download|fetch|error|timeout|deadline|failed)|raw\.githubusercontent\.com|githubusercontent\.com|context deadline exceeded"; then
    MATCHED=1
    echo "  ${RED}【发现规则集下载被墙阻断 (冷启动死锁)】${NC}"
    echo "    - 现象: sing-box 启动时拉取 remote .srs 超时。"
    echo "    - 原因: 软路由在国内直连环境下无法访问 GitHub 原始 raw 域名。"
    echo "    - ${GREEN}一键解法${NC}: 重新生成配置并附加 '--mirror jsdelivr'，使用 CDN 加速镜像。"
fi

# 特征 4: 端口冲突
if echo "$RAW_LOGS" | grep -qiE "bind: address already in use"; then
    MATCHED=1
    echo "  ${RED}【发现监听端口冲突】${NC}"
    echo "    - 现象: bind: address already in use。"
    echo "    - 原因: 53 端口或 9090 端口已被其他服务 (PassWall / OpenClash / AdGuardHome) 占用。"
    echo "    - ${GREEN}一键解法${NC}: 运行 'netstat -tulnp' 找出冲突进程并使用 '/etc/init.d/<进程> stop' 停用。"
fi

# 特征 5: OOM 物理内存耗尽
if echo "$RAW_LOGS" | grep -qiE "out of memory|killed process|fatal error: runtime: out of memory"; then
    MATCHED=1
    echo "  ${RED}【发现硬件 OOM 内存溢出崩机】${NC}"
    echo "    - 现象: 进程被 Linux 内核 OOM Killer 强行终止。"
    echo "    - 原因: 路由器 RAM 小于 256MB，加载了包含数万条域名的超大规则集，或 Go GC 延迟回收。"
    echo "    - ${GREEN}一键解法${NC}: 部署脚本已自动注入 'export GOMEMLIMIT=100MiB'；切勿加载全局非 CN 规则集！"
fi

# 特征 6: dae eBPF 加载异常
if echo "$RAW_LOGS" | grep -qiE "failed to load ebpf|bpf_prog_load|btf.*(not found|mismatch|missing)|no btf"; then
    MATCHED=1
    echo "  ${RED}【发现 dae eBPF 加载失败】${NC}"
    echo "    - 现象: failed to load ebpf 或 BTF mismatch。"
    echo "    - 原因: 官方原版 OpenWrt 内核未编译 BTF 符号。"
    echo "    - ${GREEN}一键解法${NC}: 安装 vmlinux-btf 包（第三方源提供，如 sbwml 源）；或直接改用 singbox-openwrt。"
fi

if [ "$MATCHED" -eq 0 ]; then
    echo "  ${GREEN}[✓] 未发现已知典型严重报错，服务整体运行平稳。${NC}"
fi

echo "${BOLD}================================================================${NC}"
