<#
.SYNOPSIS
    远程一键执行 OpenWrt / ImmortalWrt / iStoreOS 全维环境探针
.PARAMETER Router
    软路由 IP 地址 (如 192.168.1.1 或 192.168.6.1)
.PARAMETER User
    SSH 用户名 (默认 root)
.PARAMETER Port
    SSH 端口 (默认 22)
.PARAMETER Json
    输出 JSON 格式
.PARAMETER KeyPath
    SSH 私钥路径 (可选，默认使用系统默认密钥)
#>
# [共享脚本] 本文件与 dae-openwrt/scripts/probe.ps1 完全一致，修改需双份同步！
param(
    [Parameter(Mandatory=$true)]
    [string]$Router,

    [string]$User = "root",
    [int]$Port = 22,
    [switch]$Json,
    [string]$KeyPath = ""
)

$keyArg = if ($KeyPath) { @("-i", $KeyPath) } else { @() }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ShPath = Join-Path $ScriptDir "probe.sh"

if (-not (Test-Path $ShPath)) {
    Write-Error "[-] 探针脚本文件未找到: $ShPath"
    exit 1
}

$Arg = if ($Json) { "-j" } else { "" }
$Content = Get-Content -Raw -Path $ShPath
# 关键防护：Windows CRLF 转 Linux LF，防止 BusyBox 报 '\r': command not found
$Content = $Content -replace "`r`n", "`n"
$Content | ssh @keyArg -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 -p $Port "$User@$Router" "sh -s -- $Arg"
