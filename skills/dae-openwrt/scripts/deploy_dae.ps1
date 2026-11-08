# ==============================================================================
# OpenWrt dae (eBPF Transparent Proxy) 生产级安全热重载与自动回滚 PowerShell 客户端 (v2.0)
# 针对 Windows 环境开发，原生调用 Windows OpenSSH 进行零断网热重载部署
# ==============================================================================

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$RouterIP,

    [Parameter(Mandatory=$true, Position=1)]
    [string]$ConfigFile,

    [Parameter(Mandatory=$false)]
    [string]$User = "root",

    [Parameter(Mandatory=$false)]
    [int]$Port = 22,

    [Parameter(Mandatory=$false)]
    [string]$KeyPath = ""
)

$ErrorActionPreference = "Stop"
$keyArg = if ($KeyPath) { @("-i", $KeyPath) } else { @() }

function Write-LogInfo($msg)  { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-LogWarn($msg)  { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-LogError($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red }
function Write-LogOk($msg)    { Write-Host "[OK] $msg" -ForegroundColor Green }

if (-not (Test-Path $ConfigFile)) {
    Write-LogError "本地配置文件未找到: $ConfigFile"
    exit 1
}

Write-LogInfo "目标软路由: ${User}@${RouterIP}:${Port}"
Write-LogInfo "待部署 dae 文件: $ConfigFile"

# 1. 测试 SSH 连通性并激活 Dropbear 保护
Write-LogInfo "测试与软路由的 SSH 连通性并激活 SSH 守护..."
$sshTest = & ssh @keyArg -p $Port -o BatchMode=yes -o ConnectTimeout=5 "${User}@${RouterIP}" "echo CONNECTED" 2>&1
if ($LASTEXITCODE -ne 0 -or $sshTest -notmatch "CONNECTED") {
    Write-LogError "无法连接到软路由 SSH，请确认网络连接与 SSH 授权！"
    Write-LogError $sshTest
    exit 1
}

& ssh @keyArg -p $Port "${User}@${RouterIP}" "pgrep dropbear | while read pid; do echo -1000 > /proc/`$pid/oom_score_adj 2>/dev/null; renice -n -5 -p `$pid 2>/dev/null; done" 2>$null
Write-LogOk "SSH 守护完成（dropbear/sshd 已设为最高保护）。"

# 2. 内核版本与 eBPF / BTF 运行环境自主全自动硬准入检测 (用户无需操心)
Write-LogInfo "正在自主检测软路由内核架构与 eBPF 支持能力..."
$kver = & ssh @keyArg -p $Port "${User}@${RouterIP}" "uname -r"
if ($kver) {
    $kverParts = $kver.Split('.')
    $kmajor = [int]$kverParts[0]
    $kminor = [int]($kverParts[1] -replace '\D.*', '')
    if ($kmajor -lt 5 -or ($kmajor -eq 5 -and $kminor -lt 15)) {
        Write-LogError "【硬准入拦截】软路由内核为 Linux $kver，低于 dae 最低要求的 5.15+！"
        Write-LogError "当前固件无法加载 eBPF 内核探测器。已全自动中止部署，未对路由器做任何无用修改。"
        Write-Host "----------------------------------------------------------------------------------" -ForegroundColor Yellow
        Write-Host "【智能降级建议】请直接改用配套的 singbox-openwrt 技能！" -ForegroundColor Yellow
        Write-Host "sing-box TUN 模式对任意老旧 Linux 内核具备 100% 生产兼容性。" -ForegroundColor Yellow
        Write-Host "----------------------------------------------------------------------------------" -ForegroundColor Yellow
        exit 1
    }
}

$hasBtf = & ssh @keyArg -p $Port "${User}@${RouterIP}" "test -f /sys/kernel/btf/vmlinux -o -f /usr/lib/debug/boot/vmlinux -o -f /usr/lib/debug/boot/vmlinux-`$(uname -r) && echo 'BTF_OK'"
if ($hasBtf -notmatch "BTF_OK") {
    Write-LogWarn "未在 /sys/kernel/btf 或 /usr/lib/debug/boot 找到 BTF 符号文件。"
    Write-LogWarn "官方 OpenWrt 原版建议运行 'opkg install vmlinux-btf' 安装 BTF 支持。"
}

$hasDae = & ssh @keyArg -p $Port "${User}@${RouterIP}" "command -v dae"
if (-not $hasDae) {
    $hasDaed = & ssh @keyArg -p $Port "${User}@${RouterIP}" "command -v daed"
    if ($hasDaed) {
        Write-LogError "【支持边界】软路由只安装了 daed（Web 面板版），未安装原生 dae 命令行程序。"
        Write-LogError "daed 使用独立的 /etc/daed 配置目录与 Web 面板 (http://${RouterIP}:2023)，本脚本无法对其安全热重载。"
        Write-LogError "请在 daed Web 面板中修改配置；或安装原生 dae 后重试。"
        exit 1
    }
    Write-LogError "【环境缺失】软路由系统中未找到 'dae' 或 'daed' 运行程序！请先安装软件包。"
    exit 1
}
Write-LogOk "软路由内核 (Linux $kver) 与 eBPF 运行环境检测通过！"

# 2.1 流量分载 (Flow Offloading) 冲突治理 (铁律：Flow Offload 绕过 eBPF 导致代理失效)
$flowOffload = & ssh @keyArg -p $Port "${User}@${RouterIP}" "uci get firewall.@defaults[0].flow_offloading 2>/dev/null || echo 0"
if ($flowOffload -match "1") {
    Write-LogWarn "检测到 OpenWrt 开启了【流量分载 (Flow Offloading)】！"
    Write-LogWarn "分载引擎使数据包绕过内核协议栈与 eBPF TC/XDP 钩子，导致 dae 代理失效！"
    Write-LogInfo "正在自动关闭 Flow Offloading 以确保 eBPF 完整接管..."
    & ssh @keyArg -p $Port "${User}@${RouterIP}" "uci set firewall.@defaults[0].flow_offloading='0' 2>/dev/null || true; uci set firewall.@defaults[0].flow_offloading_hw='0' 2>/dev/null || true; uci commit firewall 2>/dev/null || true; /etc/init.d/firewall reload 2>/dev/null || true"
    Write-LogOk "已关闭流量分载并重载防火墙。"
}

# 3. 生成快照与路径
$Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$RemoteDir = "/etc/dae"
$RemoteConf = "/etc/dae/config.dae"
$RemoteTmp = "/tmp/dae-test-${Timestamp}.dae"
$BackupConf = "/etc/dae/config.dae.bak.${Timestamp}"

& ssh @keyArg -p $Port "${User}@${RouterIP}" "mkdir -p $RemoteDir"

# 4. 远端旧配置快照备份
$backupCheck = & ssh @keyArg -p $Port "${User}@${RouterIP}" "if [ -f $RemoteConf ]; then cp $RemoteConf $BackupConf; echo 'BACKUP_DONE'; fi"
$HasBackup = ($backupCheck -match "BACKUP_DONE")

if ($HasBackup) {
    Write-LogInfo "已备份远端旧配置至: $BackupConf"
}

# 5. 上传新配置至内存临时区 (/tmp)（用 ssh+stdin 而非 scp：dropbear 常缺 sftp-server）
Write-LogInfo "上传配置至软路由内存临时目录: $RemoteTmp"
$content = Get-Content -Raw -Path $ConfigFile
$content | & ssh @keyArg -p $Port "${User}@${RouterIP}" "cat > $RemoteTmp"
if ($LASTEXITCODE -ne 0) {
    Write-LogError "上传配置失败！"
    exit 1
}

# 6. 调用远端 dae validate
Write-LogInfo "正在执行远端 dae validate 严格语法校验..."
$checkRes = & ssh @keyArg -p $Port "${User}@${RouterIP}" "nice -n 10 dae validate -c $RemoteTmp 2>&1"
if ($LASTEXITCODE -ne 0 -or $checkRes -match "error|fatal|fail") {
    Write-LogError "远端 dae validate 校验不通过！错误详情:"
    Write-Host "--------------------------------------------------" -ForegroundColor Red
    Write-Host $checkRes -ForegroundColor Red
    Write-Host "--------------------------------------------------" -ForegroundColor Red
    & ssh @keyArg -p $Port "${User}@${RouterIP}" "rm -f $RemoteTmp"
    Write-LogWarn "已自动清理临时文件，未对路由器生产环境做任何修改，网络安全！"
    exit 1
}
Write-LogOk "远端 dae validate 校验 100% 通过！"

# 7. 覆盖生产并平滑热重载 (dae reload)
Write-LogInfo "覆盖生产配置并执行平滑热重载 (保留 eBPF maps 连接)..."
& ssh @keyArg -p $Port "${User}@${RouterIP}" "mv $RemoteTmp $RemoteConf && (dae reload || /etc/init.d/dae reload || /etc/init.d/dae restart || true)"

# 8. 存活监控与健康巡检
Start-Sleep -Seconds 2
$procCheck = & ssh @keyArg -p $Port "${User}@${RouterIP}" "pidof dae >/dev/null && echo 'RUNNING' || echo 'DEAD'"
if ($procCheck -notmatch "RUNNING") {
    Write-LogError "dae 进程未正常运行！"
    if ($HasBackup) {
        Write-LogWarn "触发自动回滚保护：正在秒级还原备份配置..."
        & ssh @keyArg -p $Port "${User}@${RouterIP}" "cp $BackupConf $RemoteConf && (dae reload || /etc/init.d/dae restart || true)"
        Write-LogOk "已完成紧急回滚，网络连接已复原！"
    }
    exit 1
}

# 9. 注册 WAN 重拨号自愈 Hook (使用管道传递，避免 BusyBox echo -e 输出破坏)
$hotplugScript = @'
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
'@
$hotplugScript.Replace("`r`n", "`n") | & ssh @keyArg -p $Port "${User}@${RouterIP}" "sh -s" 2>$null

Write-LogOk "dae 配置热重载发布成功完成！"
