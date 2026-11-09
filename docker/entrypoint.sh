#!/bin/sh
set -e

# 生成 Dropbear 主机密钥（若不存在）
mkdir -p /etc/dropbear /root/.ssh /var/run /var/lock /tmp/run /etc/sing-box /etc/dae /etc/nftables.d
if [ ! -f /etc/dropbear/dropbear_rsa_host_key ] && command -v dropbearkey >/dev/null 2>&1; then
    dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key -s 2048 2>/dev/null || true
fi
if [ ! -f /etc/dropbear/dropbear_ed25519_host_key ] && command -v dropbearkey >/dev/null 2>&1; then
    dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null || true
fi

# 确保 /dev/net/tun 存在 (TUN 模式所需)
if [ ! -c /dev/net/tun ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 2>/dev/null || true
    chmod 666 /dev/net/tun 2>/dev/null || true
fi

# 如果挂载或注入了测试公钥，导入 authorized_keys
if [ -f /tmp/test_key.pub ]; then
    cat /tmp/test_key.pub >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
fi

# 启动 dropbear SSH 服务监听 22 端口
if command -v dropbear >/dev/null 2>&1; then
    dropbear -R -E -p 0.0.0.0:22
    printf '%s\n' '[OpenWrt Container Ready] Dropbear SSH listening on 0.0.0.0:22.'
else
    printf '%s\n' '[OpenWrt Container Warning] Dropbear not found in container!'
fi

# 保持容器前台运行
exec /bin/sh -c 'while true; do sleep 3600; done'
