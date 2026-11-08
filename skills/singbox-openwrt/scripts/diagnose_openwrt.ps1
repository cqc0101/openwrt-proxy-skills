<#
.SYNOPSIS
    远程一键执行 OpenWrt 透明代理全链路健康体检
.PARAMETER Router
    软路由 IP 地址 (如 192.168.1.1 或 192.168.6.1)
.PARAMETER User
    SSH 用户名 (默认 root)
.PARAMETER Port
    SSH 端口 (默认 22)
.PARAMETER KeyPath
    SSH 私钥路径 (可选，默认使用系统默认密钥)
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$Router,

    [string]$User = "root",
    [int]$Port = 22,
    [string]$KeyPath = ""
)

$keyArg = if ($KeyPath) { @("-i", $KeyPath) } else { @() }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ShPath = Join-Path $ScriptDir "diagnose_openwrt.sh"

if (-not (Test-Path $ShPath)) {
    Write-Error "[-] 诊断脚本文件未找到: $ShPath"
    exit 1
}

Write-Host "[*] 正在连接软路由 $User@$Router`:$Port 执行全链路健康体检..." -ForegroundColor Cyan

# 通过 SSH 管道直接流式执行诊断脚本 (无需落盘闪存，清洗 CRLF 防报错)
$DiagnosticContent = Get-Content -Raw -Path $ShPath
$DiagnosticContent = $DiagnosticContent -replace "`r`n", "`n"
$DiagnosticContent | ssh @keyArg -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 -p $Port "$User@$Router" "sh -s"
