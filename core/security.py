# -*- coding: utf-8 -*-
"""统一 SSH 信任策略、主机密钥校验与订阅 URL / 私网白名单安全层 (SEC-001 ~ SEC-003)。"""

import ipaddress
import os
import re
import stat
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple


def _validate_private_target_host_and_ports(host: str, ports: Sequence[int]) -> Tuple[str, Tuple[int, ...]]:
    """校验并规范化私网白名单的主机名/IP 与端口列表，拦截通配符、CIDR 网段、未指定地址与非法端口。"""
    raw_h = str(host or "").strip()
    if raw_h.startswith("[") and raw_h.endswith("]"):
        raw_h = raw_h[1:-1].strip()
    norm_h = raw_h.rstrip(".").lower()
    if (
        not norm_h
        or any(ch in norm_h for ch in ("*", "?", "/", "\\"))
        or any(ord(c) <= 32 or ord(c) == 127 for c in norm_h)
        or norm_h in ("0.0.0.0", "::", "localhost")
    ):
        raise ValueError(f"[SEC-002] 严禁使用通配符、CIDR 网段或未指定地址作为私网白名单主机: {host!r}")

    bare_ip = norm_h.split("%", 1)[0]
    try:
        ip_obj = ipaddress.ip_address(bare_ip)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        if ip_obj.is_unspecified or ip_obj.is_multicast:
            raise ValueError(f"[SEC-002] 严禁将未指定或多播地址加入私网白名单: {host!r}")
        if "%" not in norm_h:
            norm_h = str(ip_obj)
    elif ":" in norm_h:
        # 既不是合法 IPv6 字面量又包含冒号（例如 ':' 或残留端口）
        raise ValueError(f"[SEC-002] 非法的私网白名单主机名或 IPv6 地址: {host!r}")

    if not ports:
        raise ValueError(f"[SEC-002] 私网白名单必须至少绑定一个有效端口: {host!r}")
    clean_ports: List[int] = []
    for p in ports:
        if isinstance(p, bool) or not isinstance(p, int) or not (1 <= int(p) <= 65535):
            raise ValueError(f"[SEC-002] 私网白名单端口超出合法范围 (1-65535): {p!r}")
        clean_ports.append(int(p))
    return norm_h, tuple(clean_ports)


@dataclass(frozen=True)
class AllowedPrivateTarget:
    """受控的私网订阅例外白名单条目：必须绑定明确的主机名/IP、端口列表与用途。"""
    host: str
    ports: Tuple[int, ...] = (443, 80)
    purpose: str = "user_self_hosted_subscription"

    def __post_init__(self) -> None:
        norm_h, clean_ports = _validate_private_target_host_and_ports(self.host, self.ports)
        object.__setattr__(self, "host", norm_h)
        object.__setattr__(self, "ports", clean_ports)

    def matches(self, hostname: str, port: int) -> bool:
        if isinstance(port, bool):
            return False
        try:
            port_int = int(port)
        except (ValueError, TypeError):
            return False
        if port_int not in self.ports:
            return False
        norm_target = str(self.host or "").strip().strip("[]").rstrip(".").lower()
        norm_host = str(hostname or "").strip().strip("[]").rstrip(".").lower()
        if not norm_target or not norm_host:
            return False
        if norm_target == norm_host:
            return True
        try:
            ip_t = ipaddress.ip_address(norm_target.split("%", 1)[0])
            ip_h = ipaddress.ip_address(norm_host.split("%", 1)[0])
            return ip_t == ip_h
        except ValueError:
            return False


@dataclass(frozen=True)
class SSHPolicy:
    """生产环境软路由 SSH 安全连接策略模型 (默认强制 StrictHostKeyChecking=yes)。"""
    host: str
    port: int = 22
    username: str = "root"
    known_hosts_file: Optional[Path] = None
    identity_file: Optional[Path] = None
    strict_host_key_checking: bool = True
    connect_timeout: int = 8
    command_timeout: int = 30
    allow_agent: bool = False
    allow_password_auth: bool = False
    expected_fingerprint: Optional[str] = None


def verify_private_key_file(key_path: Path, check_permissions: bool = True) -> Path:
    """校验 SSH 私钥路径合法性、存在性及文件权限（POSIX 下拒绝 group/world 可读私钥）。"""
    raw = str(key_path or "").strip()
    if not raw or raw.startswith("-") or re.search(r"[\r\n\x00]", raw):
        raise ValueError(f"[SEC-001] 非法的 SSH 私钥路径: {raw!r}")
    p = Path(raw)
    if not p.is_file():
        raise ValueError(f"[SEC-001] SSH 私钥文件不存在: {raw}")
    if check_permissions and os.name != "nt":
        mode = stat.S_IMODE(p.stat().st_mode)
        if mode & 0o077:
            raise PermissionError(
                f"[SEC-001] SSH 私钥权限过宽 ({oct(mode)})，拒绝使用 group/other 可读私钥: {raw}"
            )
    return p


def verify_known_hosts_file(kh_path: Path, check_permissions: bool = True) -> Path:
    """校验 known_hosts 文件路径合法性、存在性及写权限安全（拒绝 group/world 可写 known_hosts）。"""
    raw = str(kh_path or "").strip()
    if not raw or raw.startswith("-") or re.search(r"[\r\n\s\x00]", raw):
        raise ValueError(f"[SEC-001] 非法的 known_hosts 路径: {raw!r}")
    p = Path(raw)
    if not p.is_file():
        raise ValueError(f"[SEC-001] 指定的 known_hosts 文件不存在: {raw}")
    if check_permissions and os.name != "nt":
        mode = stat.S_IMODE(p.stat().st_mode)
        if mode & 0o022:
            raise PermissionError(
                f"[SEC-001] known_hosts 权限不安全 ({oct(mode)})，拒绝使用可被其他用户篡改的文件: {raw}"
            )
    return p


def validate_ssh_policy(policy: SSHPolicy, check_files: bool = True) -> None:
    """对 SSHPolicy 执行全量边界与安全检查。"""
    host = str(policy.host or "").strip()
    user = str(policy.username or "").strip()
    if not host or host.startswith("-") or re.search(r"[\s\x00]", host):
        raise ValueError(f"[SEC-001] 非法的目标主机地址: {policy.host!r}")
    if not user or user.startswith("-") or re.search(r"[\s\x00]", user):
        raise ValueError(f"[SEC-001] 非法的 SSH 用户名: {policy.username!r}")
    if isinstance(policy.port, bool) or not (1 <= int(policy.port) <= 65535):
        raise ValueError(f"[SEC-001] SSH 端口超出合法范围 (1-65535): {policy.port!r}")
    if isinstance(policy.connect_timeout, bool) or not (1 <= int(policy.connect_timeout) <= 60):
        raise ValueError(f"[SEC-001] SSH 连接超时超出范围 (1-60s): {policy.connect_timeout!r}")
    if isinstance(policy.command_timeout, bool) or not (1 <= int(policy.command_timeout) <= 300):
        raise ValueError(f"[SEC-001] SSH 命令超时超出范围 (1-300s): {policy.command_timeout!r}")
    if policy.expected_fingerprint is not None:
        raise ValueError("[SEC-001] expected_fingerprint 尚未实现握手级校验；请通过 known_hosts 固定主机密钥")
    if policy.strict_host_key_checking and policy.known_hosts_file is not None and check_files:
        verify_known_hosts_file(policy.known_hosts_file)
    if policy.identity_file is not None and check_files:
        verify_private_key_file(policy.identity_file)


def build_ssh_command(policy: SSHPolicy, remote_argv: Sequence[str], check_files: bool = True) -> List[str]:
    """根据 SSHPolicy 生成参数化 SSH 命令数组，严禁拼入未经校验的字符串。"""
    validate_ssh_policy(policy, check_files=check_files)
    hk_mode = "yes" if policy.strict_host_key_checking else "accept-new"
    cmd: List[str] = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", f"StrictHostKeyChecking={hk_mode}",
        "-o", f"ConnectTimeout={int(policy.connect_timeout)}",
        "-o", "ServerAliveInterval=10",
        "-o", "ServerAliveCountMax=2",
        "-o", "LogLevel=ERROR",
    ]
    if not policy.allow_password_auth:
        cmd.extend(["-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no"])
    if not policy.allow_agent:
        cmd.extend(["-o", "IdentitiesOnly=yes", "-o", "ForwardAgent=no"])
    if policy.known_hosts_file is not None:
        cmd.extend(["-o", f"UserKnownHostsFile={policy.known_hosts_file}"])
    if policy.identity_file is not None:
        cmd.extend(["-i", str(policy.identity_file)])
    cmd.extend(["-p", str(int(policy.port)), "--", f"{policy.username}@{policy.host}"])
    if isinstance(remote_argv, (str, bytes)) or not remote_argv:
        raise ValueError("[SEC-001] 远端命令必须为非空参数序列")
    args = []
    for arg in remote_argv:
        if not isinstance(arg, str) or any(ord(c) < 32 or ord(c) == 127 for c in arg):
            raise ValueError("[SEC-001] 远端命令参数必须为无控制字符的字符串")
        args.append(shlex.quote(arg))
    # OpenSSH joins argv with spaces and sends a command to the remote shell.
    # Local argv boundaries do not provide remote shell quoting.
    cmd.append(" ".join(args))
    return cmd


def parse_allowed_private_targets(spec: str) -> List[AllowedPrivateTarget]:
    """解析形如 '192.168.1.10:25500,sub.home.arpa:443|8443,[fe80::1]:25500' 的精确私网白名单配置。"""
    targets: List[AllowedPrivateTarget] = []
    for raw_item in str(spec or "").split(","):
        item = raw_item.strip()
        if not item:
            continue
        if item.startswith("[") or "]" in item:
            # IPv6 [fe80::1]:25500 或 [fe80::1]
            m = re.match(r"^\[([^\]]+)\](?::([0-9|]+))?$", item)
            if not m:
                raise ValueError(f"[SEC-002] 非法的私网白名单条目: {item!r}")
            host_part, port_part = m.group(1), m.group(2)
        elif item.count(":") == 1:
            host_part, port_part = item.rsplit(":", 1)
        elif item.count(":") > 1:
            # 裸 IPv6 地址（未带端口）或非法的 '::'
            host_part, port_part = item, "443|80"
        else:
            host_part, port_part = item, "443|80"

        ports: List[int] = []
        for p_str in (port_part or "443|80").split("|"):
            p_s = p_str.strip()
            if not p_s.isdigit():
                raise ValueError(f"[SEC-002] 非法的私网白名单端口: {item!r}")
            p_int = int(p_s)
            if not (1 <= p_int <= 65535):
                raise ValueError(f"[SEC-002] 私网白名单端口超出范围: {p_int}")
            ports.append(p_int)
        targets.append(AllowedPrivateTarget(host=host_part, ports=tuple(ports)))
    return targets
