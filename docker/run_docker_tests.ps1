<#
.SYNOPSIS
    OpenWrt 自动化测试流水线 (PowerShell 版)
.DESCRIPTION
    调度本地 Docker 容器或 Mock 仿真服务，对 singbox-openwrt 与 dae-openwrt 技能进行自动化验证。
.PARAMETER Mode
    运行基座模式：Auto (默认), Docker, Mock
.PARAMETER Port
    SSH 端口 (默认 2222)
.PARAMETER KeyPath
    SSH 私钥路径 (可选，默认使用 .deploy_key/id_ed25519)
#>
[CmdletBinding()]
param(
    [ValidateSet("Auto", "Docker", "Mock")]
    [string]$Mode = "Auto",
    [int]$Port = 2222,
    [string]$KeyPath = "",
    [switch]$KeepAlive
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " OpenWrt 技能测试流水线 (PowerShell 调度器)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 优先选择包含 paramiko 的虚拟环境 Python 解释器
$PyCmd = "python"
if (Test-Path "C:\Users\Administrator\venv\Scripts\python.exe") {
    $PyCmd = "C:\Users\Administrator\venv\Scripts\python.exe"
} elseif (Get-Command "python3" -ErrorAction SilentlyContinue) {
    $PyCmd = "python3"
}

$ScriptPath = Join-Path $PSScriptRoot "run_docker_tests.py"
$ArgsList = @($ScriptPath, "--mode", $Mode.ToLower(), "--port", $Port)
if ($KeyPath) {
    $ArgsList += @("--key", $KeyPath)
}
if ($KeepAlive) {
    $ArgsList += "--keep-alive"
}

& $PyCmd $ArgsList
exit $LASTEXITCODE
