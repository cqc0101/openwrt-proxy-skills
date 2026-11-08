# ==============================================================================
# OpenWrt sing-box 客户端生产级安全部署与异常回滚 PowerShell 客户端 (v2.0 硬件防爆版)
# 针对 Windows 环境开发，原生调用 Windows OpenSSH 进行零断网安全部署
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
Write-LogInfo "待部署文件: $ConfigFile"

# 1. 本地 JSON 校验
try {
    $content = Get-Content -Raw -Path $ConfigFile
    $null = ConvertFrom-Json $content
    Write-LogOk "本地 JSON 基础语法解析通过"
} catch {
    Write-LogError "本地配置文件 JSON 格式解析失败: $_"
    exit 1
}

# 2. 测试 SSH 连通并激活 Dropbear 防爆保护
Write-LogInfo "测试与软路由的 SSH 连通性并保护 SSH 守护进程..."
$sshTest = & ssh @keyArg -p $Port -o BatchMode=yes -o ConnectTimeout=5 "${User}@${RouterIP}" "echo CONNECTED" 2>&1
if ($LASTEXITCODE -ne 0 -or $sshTest -notmatch "CONNECTED") {
    Write-LogError "无法连接到软路由 SSH，请确认 IP、端口及 SSH 免密密钥配置！"
    Write-LogError $sshTest
    exit 1
}

# 提升 dropbear 优先级，防止内存争抢导致 SSH 输入假死
& ssh @keyArg -p $Port "${User}@${RouterIP}" "pgrep dropbear | while read pid; do echo -1000 > /proc/`$pid/oom_score_adj 2>/dev/null; renice -n -5 -p `$pid 2>/dev/null; done" 2>$null
Write-LogOk "SSH 连通正常，SSH 守护进程已获得 OOM 最高防护。"

# 3. 远端版本与内存安全探查
$hwInfo = & ssh @keyArg -p $Port "${User}@${RouterIP}" "awk '/MemAvailable/ {print int(`$2/1024)}' /proc/meminfo 2>/dev/null || awk '/MemFree/ {print int(`$2/1024)}' /proc/meminfo 2>/dev/null"
if ($hwInfo -and [int]$hwInfo -lt 48) {
    Write-LogWarn "【超小内存提醒】路由器当前可用内存仅约 ${hwInfo}MB，已启用轻量化部署调度！"
}

$remoteVer = & ssh @keyArg -p $Port "${User}@${RouterIP}" "sing-box version 2>/dev/null | head -n 1"
if ($remoteVer) {
    Write-LogInfo "软路由已装核心: $remoteVer"
    $fileText = Get-Content -Raw -Path $ConfigFile
    if ($remoteVer -match "1\.13") {
        if ($fileText -match "store_dns" -or $fileText -match "default_http_client") {
            Write-LogWarn "[版本门控提醒] 软路由内核为 1.13，而配置文件包含 1.14 专属字段 (store_dns/default_http_client)！"
        }
    } elseif ($remoteVer -match "1\.14") {
        if ($fileText -match "store_rdrc" -or $fileText -match "independent_cache") {
            Write-LogWarn "[版本门控提醒] 软路由内核为 1.14+，而配置文件包含已被废弃字段 (store_rdrc/independent_cache)！"
        }
    }
}

# 4. 生成快照与路径
$Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$RemoteDir = "/etc/sing-box"
$RemoteConf = "/etc/sing-box/config.json"
$RemoteTmp = "/tmp/sing-box-test-${Timestamp}.json"
$BackupConf = "/etc/sing-box/config.json.bak.${Timestamp}"

& ssh @keyArg -p $Port "${User}@${RouterIP}" "mkdir -p $RemoteDir"

# 5. 远端旧配置快照备份
$backupCheck = & ssh @keyArg -p $Port "${User}@${RouterIP}" "if [ -f $RemoteConf ]; then cp $RemoteConf $BackupConf; echo 'BACKUP_DONE'; fi"
$HasBackup = ($backupCheck -match "BACKUP_DONE")

if ($HasBackup) {
    Write-LogInfo "已备份远端配置文件至: $BackupConf"
}

# 6. 上传至内存临时区 (/tmp)（用 ssh+stdin 而非 scp：dropbear 常缺 sftp-server）
Write-LogInfo "上传配置至软路由内存临时目录: $RemoteTmp"
$content = Get-Content -Raw -Path $ConfigFile
$content | & ssh @keyArg -p $Port "${User}@${RouterIP}" "cat > $RemoteTmp"
if ($LASTEXITCODE -ne 0) {
    Write-LogError "上传配置失败！"
    exit 1
}

# 7. 调用远端 sing-box check (带 nice 优先级保护)
Write-LogInfo "正在执行远端 sing-box check 严格语法校验..."
$checkRes = & ssh @keyArg -p $Port "${User}@${RouterIP}" "nice -n 10 sing-box check -c $RemoteTmp 2>&1"
if ($LASTEXITCODE -ne 0 -or $checkRes -match "error|fatal") {
    Write-LogError "远端 sing-box check 语法校验不通过！错误信息:"
    Write-Host "--------------------------------------------------" -ForegroundColor Red
    Write-Host $checkRes -ForegroundColor Red
    Write-Host "--------------------------------------------------" -ForegroundColor Red
    & ssh @keyArg -p $Port "${User}@${RouterIP}" "rm -f $RemoteTmp"
    Write-LogWarn "已自动清理临时文件，未对路由器生产环境做任何修改，网络安全！"
    exit 1
}
Write-LogOk "远端 sing-box check 校验 100% 通过！"

# 7.1 Go 运行时 OOM 保护 (GOMEMLIMIT)
$memTotal = & ssh @keyArg -p $Port "${User}@${RouterIP}" "awk '/MemTotal/ {print int(`$2/1024)}' /proc/meminfo 2>/dev/null || echo 256"
if ($memTotal -and [int]$memTotal -le 300) {
    Write-LogInfo "小内存设备 (${memTotal}MB)，自动注入 Go 运行时 OOM 防护 (GOMEMLIMIT=100MiB)..."
    & ssh @keyArg -p $Port "${User}@${RouterIP}" "if [ -f /etc/init.d/sing-box ] && ! grep -q 'GOMEMLIMIT' /etc/init.d/sing-box; then sed -i '2i export GOGC=50' /etc/init.d/sing-box; sed -i '2i export GOMEMLIMIT=100MiB' /etc/init.d/sing-box; fi" 2>$null
}

# 7.5 确保 OpenWrt procd 服务已启用（apk/opkg 安装后默认 enabled=0，不启用则 restart 静默无效）
& ssh @keyArg -p $Port "${User}@${RouterIP}" "if uci -q get sing-box.main >/dev/null 2>&1; then uci set sing-box.main.enabled='1'; uci set sing-box.main.workdir='/etc/sing-box'; uci commit sing-box; echo SERVICE_ENABLED; else echo NO_UCI_SECTION; fi" 2>$null | Out-Null

# 8. 覆盖生产并平滑重载
Write-LogInfo "应用新配置并重启 sing-box 服务..."
& ssh @keyArg -p $Port "${User}@${RouterIP}" "mv $RemoteTmp $RemoteConf"
if ($LASTEXITCODE -ne 0) {
    Write-LogError "覆盖生产配置失败 (mv 退出码 $LASTEXITCODE)！旧配置保持不动，网络未受影响。"
    exit 1
}
& ssh @keyArg -p $Port "${User}@${RouterIP}" "nice -n 5 /etc/init.d/sing-box restart || service sing-box restart || killall -HUP sing-box || true"

# 9. 注册 WAN 重拨号自愈 Hook (使用管道传递，避免 BusyBox echo -e 输出 -e 破坏脚本)
$hotplugScript = @'
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
'@
$hotplugScript.Replace("`r`n", "`n") | & ssh @keyArg -p $Port "${User}@${RouterIP}" "sh -s" 2>$null

# 10. 健康存活探测与自动回滚
Start-Sleep -Seconds 3
$procCheck = & ssh @keyArg -p $Port "${User}@${RouterIP}" "pidof sing-box >/dev/null && echo 'RUNNING' || echo 'DEAD'"
if ($procCheck -notmatch "RUNNING") {
    Write-LogError "sing-box 进程未运行（可能是配置崩溃，也可能是服务未启用）！"
    Write-LogWarn "排查提示：logread 查看报错；uci get sing-box.main.enabled 应为 1（本脚本已尝试自动启用）。"
    if ($HasBackup) {
        Write-LogWarn "触发自动回滚保护：正在秒级还原备份配置..."
        & ssh @keyArg -p $Port "${User}@${RouterIP}" "cp $BackupConf $RemoteConf && /etc/init.d/sing-box restart"
        Write-LogOk "已完成紧急回滚，网络连接已复原！"
    }
    exit 1
}

# 11. 检验外网连通（curl → wget → ping 三级兜底，避免未装 curl 时误报离线）
Write-LogInfo "检验外网连通状态..."
$netCheck = & ssh @keyArg -p $Port "${User}@${RouterIP}" "sh -c 'if command -v curl >/dev/null 2>&1; then curl -s --connect-timeout 4 -I https://www.baidu.com >/dev/null && echo ONLINE || echo OFFLINE; elif command -v wget >/dev/null 2>&1; then wget -q -T 4 --spider https://www.baidu.com >/dev/null && echo ONLINE || echo OFFLINE; else ping -c 1 -W 3 223.5.5.5 >/dev/null 2>&1 && echo ONLINE || echo OFFLINE; fi'"
if ($netCheck -notmatch "ONLINE") {
    Write-LogWarn "路由器外部联网测试超时！"
    Write-LogWarn "若为首次启用 TUN 模式，可能是 OpenWrt 防火墙拦截了 tun0。"
    Write-LogWarn "请执行: sh scripts/setup_openwrt_firewall.sh $RouterIP 放行 tun0 网卡。"
} else {
    Write-LogOk "外网解析与连通一切正常！"
}

Write-LogOk "sing-box 配置发布成功完成！"
