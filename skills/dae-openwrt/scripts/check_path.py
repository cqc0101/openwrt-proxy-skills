#!/usr/bin/env python3
"""Bounded HTTPS checks from a LAN client; does not change routes, DNS or services."""
import argparse
import ipaddress
import json
import os
import subprocess
from urllib.parse import urlsplit


def check_url(value):
    u = urlsplit(value)
    if u.scheme != "https" or not u.hostname or u.username is not None or u.password is not None:
        raise ValueError("HTTPS URL without userinfo required")
    if u.port not in (None, 443) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("invalid URL")
    return value


def run_check(url, interface, resolve=(), timeout=10, curl="curl", max_bytes=262144):
    check_url(url)
    if not interface or interface.startswith("-") or any(ord(c) < 32 for c in interface):
        raise ValueError("explicit source interface or address required")
    if not 1 <= timeout <= 30 or not 1 <= max_bytes <= 1048576:
        raise ValueError("test bounds exceeded")
    args = [curl, "--interface", interface, "--noproxy", "*", "--connect-timeout", str(min(5, timeout)),
            "--max-time", str(timeout), "--max-filesize", str(max_bytes), "--limit-rate", "256K",
            "--silent", "--show-error", "--output", os.devnull,
            "--write-out", "%{http_code} %{local_ip} %{remote_ip} %{size_download} %{speed_download} %{time_total}"]
    explicit_dns = False
    host = urlsplit(url).hostname
    for entry in resolve:
        name, sep, address = entry.partition("=")
        if not sep or not name or any(c in name for c in ":/\\\r\n"):
            raise ValueError("resolve requires HOST=IP")
        ip = ipaddress.ip_address(address)
        if name.lower() == host.lower():
            explicit_dns = True
        literal = "[" + str(ip) + "]" if ip.version == 6 else str(ip)
        args += ["--resolve", name + ":443:" + literal]
    args += [url]
    result = {"host": host, "source_requested": interface, "dns_mode": "explicit_answer" if explicit_dns else "system_resolver",
              "dns_server_verified": False, "max_bytes": max_bytes, "timeout_seconds": timeout}
    try:
        p = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", timeout=timeout + 3)
    except (OSError, subprocess.TimeoutExpired):
        return dict(result, status="tool_error", success=False)
    result["curl_exit"] = p.returncode
    if p.returncode in (2, 3, 4, 48):
        return dict(result, status="tool_error", success=False)
    try:
        code, local, remote, size, speed, elapsed = p.stdout.strip().split()
        result.update(http_code=int(code), local_ip=str(ipaddress.ip_address(local)), remote_ip=str(ipaddress.ip_address(remote)),
                      bytes_received=int(size), speed_bytes_per_second=float(speed), elapsed_seconds=float(elapsed))
    except (ValueError, TypeError):
        return dict(result, status="request_failed" if p.returncode else "tool_error", success=False)
    success = p.returncode == 0 and 200 <= result["http_code"] < 400
    return dict(result, status="passed" if success else "request_failed", success=success)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--interface", required=True)
    p.add_argument("--url", action="append", required=True)
    p.add_argument("--resolve", action="append", default=[], metavar="HOST=IP")
    p.add_argument("--timeout", type=int, default=10)
    a = p.parse_args()
    try:
        if len(a.url) > 8:
            raise ValueError("at most eight requests")
        checks = [run_check(u, a.interface, a.resolve, a.timeout) for u in a.url]
    except ValueError:
        p.exit(2, "Invalid test arguments.\n")
    print(json.dumps({"scope": "client_https_sample", "node_identity_verified": False,
                      "dns_path_verified": False, "max_bandwidth_measured": False, "checks": checks}, ensure_ascii=False, indent=2))
    return 0 if all(c["success"] for c in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
