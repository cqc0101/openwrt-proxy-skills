# -*- coding: utf-8 -*-
"""轻量高仿真 OpenWrt SSH 测试服务端 (Mock Server)。

当本地尚未启动 Docker 容器或在无 Docker 守护进程的环境下，
提供标准 SSH 协议 (监听 127.0.0.1:2222) 的 OpenWrt 仿真环境，
支持探针探测 (probe)、配置下发 (deploy)、防火墙注入 (fw4) 与 7 步全链路诊断。
"""

import io
import json
import os
import re
import socket
import sys
import threading
import time

try:
    import paramiko
except ImportError:
    paramiko = None


class OpenWrtState:
    """保存仿真 OpenWrt 的运行时与 UCI 状态。"""

    def __init__(self):
        self.arch = "x86_64"
        self.kernel = "6.1.38"
        self.os_release = (
            'NAME="OpenWrt"\n'
            'VERSION="23.05.5"\n'
            'ID="openwrt"\n'
            'PRETTY_NAME="OpenWrt 23.05.5"'
        )
        self.openwrt_release = (
            "DISTRIB_ID='OpenWrt'\n"
            "DISTRIB_RELEASE='23.05.5'\n"
            "DISTRIB_REVISION='r23885-bee52e048a'\n"
            "DISTRIB_TARGET='x86/64'\n"
            "DISTRIB_ARCH='x86_64'\n"
            "DISTRIB_DESCRIPTION='OpenWrt 23.05.5 r23885-bee52e048a'"
        )
        self.lan_dev = "br-lan"
        self.wan_dev = "eth0"
        self.fw_zone_lan_devices = ["tun0"]
        self.singbox_enabled = True
        self.singbox_running = True
        self.singbox_pid = 13150
        self.files = {}
        self.log_buffer = ["sing-box[13150]: sing-box started (version 1.14.3)"]

    def execute_command(self, cmd_line, stdin_data=""):
        cmd = cmd_line.strip()

        # 检查是否为 JSON 诊断/探针脚本调用
        if ("--json" in cmd or "-j" in cmd) and ("doctor.sh" in stdin_data or "Smart Log Doctor" in stdin_data):
            return json.dumps({
                "service": "sing-box",
                "status": "healthy",
                "overall_code": 0,
                "singbox_running": self.singbox_running,
                "dae_running": False,
                "tun_alive": True,
                "fw_tun_ok": "tun0" in self.fw_zone_lan_devices,
                "port53_open": True,
                "outbound_ok": True,
                "issue_count": 0,
                "issues": [],
                "suggested_actions": [],
            }), 0
        if ("--json" in cmd or "-j" in cmd) and ("diagnose_dns.sh" in stdin_data or "DNS 深度健康体检" in stdin_data):
            return json.dumps({
                "total_checks": 7,
                "passed_checks": 7,
                "warnings": 0,
                "errors": 0,
                "dns_holder": "Dnsmasq",
                "port53_open": True,
                "checks": [{"status": "pass", "message": "ok"}] * 7,
            }), 0

        # 检查是否为诊断全量脚本
        if "diagnose_openwrt" in cmd or "全链路健康诊断" in stdin_data or "CHECK 1/7" in stdin_data:
            return self.simulate_diagnosis(), 0

        # 复合脚本或多行输入处理 (例如 sh -s 或 tr -d '\r' | sh -s)
        if "sh -s" in cmd or cmd.startswith("sh"):
            script = stdin_data if stdin_data else cmd
            sub_outputs = []
            for subcmd in script.splitlines():
                subcmd = subcmd.strip()
                if not subcmd or subcmd.startswith("#") or subcmd.startswith("case") or subcmd in ("esac", "fi", "HOTPLUG_EOF"):
                    continue
                out, rc = self.execute_single_command(subcmd)
                if out:
                    sub_outputs.append(out)
            return "\n".join(sub_outputs), 0

        return self.execute_single_command(cmd)

    def simulate_diagnosis(self):
        return (
            "=================================================================\n"
            " OpenWrt 透明代理全链路健康体检 (7 步体检)\n"
            "=================================================================\n"
            "[CHECK 1/7] 检查 sing-box 进程运行状态...\n"
            "  [✔] sing-box 正在运行中 (PID: 13150, 物理内存: 46MB)\n"
            "[CHECK 2/7] 检查 TUN 虚拟网卡 (tun0)...\n"
            "  [✔] tun0 虚拟网卡已创建并处于 UP 状态 (IPv4: 172.19.0.1)\n"
            "[CHECK 3/7] 检查防火墙 LAN 区域放行...\n"
            "  [✔] tun0 已正确添加至防火墙 @zone[0] (lan 区域)\n"
            "[CHECK 4/7] 检查 Clash API 控制端口 (9090)...\n"
            "  [✔] 9090 端口监听正常 (sing-box Clash RESTful API 就绪)\n"
            "[CHECK 5/7] 检查 DNS 分流与防污染...\n"
            "  [✔] 核心 DNS 监听 53 端口正常 (未发生环路死锁)\n"
            "[CHECK 6/7] 检查闪存与内存防磨损策略...\n"
            "  [✔] 缓存路径位于 /tmp (tmpfs)，未磨损路由器 Flash 存储\n"
            "[CHECK 7/7] 检查核心运行日志与最近错误...\n"
            "  [✔] 最近 50 行日志未见 fatal/panic/segmentation fault 致命错误\n"
            "=================================================================\n"
            "【诊断结论】全链路 7 项体检 100% 通过！透明代理与网络转发处于最佳状态。\n"
            "================================================================="
        )

    def execute_single_command(self, cmd):
        # 基础架构与版本
        if cmd.startswith("uname -m"):
            return self.arch, 0
        if cmd.startswith("uname -r"):
            return self.kernel, 0
        if cmd.startswith("uname -a"):
            return f"Linux OpenWrt {self.kernel} #1 SMP PREEMPT x86_64 GNU/Linux", 0
        if "cat /etc/os-release" in cmd:
            return self.os_release, 0
        if "cat /etc/openwrt_release" in cmd:
            return self.openwrt_release, 0

        # 防火墙与工具探测
        if "which nft" in cmd or "command -v nft" in cmd:
            return "/usr/sbin/nft", 0
        if "which iptables" in cmd or "command -v iptables" in cmd:
            return "", 1
        if "which sing-box" in cmd or "command -v sing-box" in cmd:
            return "/usr/bin/sing-box", 0
        if "which dae" in cmd or "command -v dae" in cmd:
            return "", 1
        if "which daed" in cmd or "command -v daed" in cmd:
            return "", 1
        if "grep -q btf /sys/kernel/btf/vmlinux" in cmd:
            return "", 1
        if "grep nfqueue /proc/net/ip_tables_targets" in cmd:
            return "", 1

        # 网卡与路由
        if "uci get network.lan.device" in cmd:
            return self.lan_dev, 0
        if "uci get network.wan.device" in cmd:
            return self.wan_dev, 0
        if "ip route show default" in cmd or "ip route" in cmd:
            return f"default via 192.168.1.1 dev {self.wan_dev} proto dhcp", 0
        if "ip link" in cmd or "ip addr" in cmd:
            return (
                f"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
                f"2: {self.wan_dev}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                f"3: {self.lan_dev}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                f"4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 9000\n"
                f"    inet 172.19.0.1/30 scope global tun0"
            ), 0

        # 防火墙 UCI
        if "uci get firewall.@zone[0].name" in cmd:
            return "lan", 0
        if "uci get firewall.@zone[0].device" in cmd:
            return " ".join(self.fw_zone_lan_devices), 0
        if "uci show firewall" in cmd:
            dev_lines = []
            for d in self.fw_zone_lan_devices:
                dev_lines.append(f"firewall.@zone[0].device='{d}'")
            dev_part = "\n" + "\n".join(dev_lines) if dev_lines else ""
            return (
                "firewall.@defaults[0]=defaults\n"
                "firewall.@zone[0]=zone\n"
                "firewall.@zone[0].name='lan'\n"
                "firewall.@zone[0].network='lan'"
                f"{dev_part}\n"
                "firewall.@zone[1]=zone\n"
                "firewall.@zone[1].name='wan'\n"
                "firewall.@zone[1].network='wan'"
            ), 0
        if "uci add_list firewall.@zone[0].device=" in cmd:
            device_match = re.search(r"device=['\"]?([a-zA-Z0-9_\-]+)", cmd)
            if device_match:
                dev = device_match.group(1)
                if dev not in self.fw_zone_lan_devices:
                    self.fw_zone_lan_devices.append(dev)
            return "", 0
        if "uci commit firewall" in cmd:
            return "", 0
        if "/etc/init.d/firewall restart" in cmd:
            return "[OK] firewall restarted", 0

        # sing-box UCI 与服务控制
        if "uci set sing-box.main.enabled=" in cmd:
            self.singbox_enabled = ("'1'" in cmd or '"1"' in cmd or "1" in cmd)
            return "", 0
        if "uci get sing-box.main.enabled" in cmd:
            return "1" if self.singbox_enabled else "0", 0
        if "uci commit sing-box" in cmd:
            return "", 0
        if "sing-box version" in cmd:
            return "sing-box version 1.14.3", 0
        if "sing-box check" in cmd:
            m = re.search(r"-c\s+(\S+)", cmd)
            if m:
                path = m.group(1)
                content = self.files.get(path, "")
                if content:
                    try:
                        cfg = json.loads(content)
                        if "inbounds" in cfg and "outbounds" in cfg:
                            return "configuration check passed", 0
                    except Exception:
                        return "invalid json syntax", 1
            return "configuration check passed", 0
        if "/etc/init.d/sing-box restart" in cmd or "service sing-box restart" in cmd:
            self.singbox_running = True
            return "[OK] sing-box restarted", 0
        if "pidof sing-box" in cmd:
            if self.singbox_running:
                return str(self.singbox_pid), 0
            return "", 1
        if "netstat" in cmd or "ss -tlpn" in cmd or "ss -lnt" in cmd:
            if self.singbox_running:
                return "tcp 0 0 0.0.0.0:9090 0.0.0.0:* LISTEN 13150/sing-box", 0
            return "", 0
        if "logread" in cmd:
            return "\n".join(self.log_buffer), 0

        # 内存与空间探查
        if "MemAvailable" in cmd or "MemFree" in cmd:
            return "512", 0
        if "MemTotal" in cmd:
            return "1024", 0
        if "df -m /tmp" in cmd or "df -m /overlay" in cmd or "df" in cmd:
            return "Filesystem 1M-blocks Used Available Use% Mounted on\n/dev/root 500 50 450 10% /\ntmpfs 512 2 510 1% /tmp", 0
        if "free -m" in cmd or "free" in cmd:
            return "              total        used        free      shared  buff/cache   available\nMem:           1024         128         800           8          96         850", 0

        # 联网测试 (curl/wget/ping)
        if "echo ONLINE" in cmd:
            return "ONLINE", 0
        if "echo CONNECTED" in cmd:
            return "CONNECTED", 0

        # 文件操作：例如 cp /tmp/config.json /etc/sing-box/config.json
        if cmd.startswith("cp ") or "cp /tmp/" in cmd:
            parts = cmd.split()
            if len(parts) >= 3:
                src, dst = parts[1], parts[2]
                if src in self.files:
                    self.files[dst] = self.files[src]
            return "", 0
        if cmd.startswith("mv "):
            parts = cmd.split()
            if len(parts) >= 3:
                src, dst = parts[1], parts[2]
                if src in self.files:
                    self.files[dst] = self.files[src]
            return "", 0
        if cmd.startswith("mkdir") or cmd.startswith("rm "):
            return "", 0

        # 兜底成功响应
        return "", 0


if paramiko is not None:
    class MockSSHServer(paramiko.ServerInterface):
        def __init__(self, state):
            self.state = state
            self.event = threading.Event()

        def check_channel_request(self, kind, chanid):
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_auth_password(self, username, password):
            return paramiko.AUTH_SUCCESSFUL

        def check_auth_publickey(self, username, key):
            return paramiko.AUTH_SUCCESSFUL

        def get_allowed_auths(self, username):
            return "password,publickey"

        def check_channel_exec_request(self, channel, command):
            cmd_str = command.decode("utf-8", errors="replace") if isinstance(command, bytes) else command
            threading.Thread(target=self._handle_exec, args=(channel, cmd_str), daemon=True).start()
            return True

        def check_channel_shell_request(self, channel):
            threading.Thread(target=self._handle_shell, args=(channel,), daemon=True).start()
            return True

        def check_channel_subsystem_request(self, channel, name):
            if name == "sftp":
                return True
            return False

        def _handle_exec(self, channel, command):
            stdin_data = b""
            if "cat >" in command or "sh -s" in command:
                while True:
                    try:
                        chunk = channel.recv(4096)
                        if not chunk:
                            break
                        stdin_data += chunk
                    except Exception:
                        break
            elif channel.recv_ready():
                try:
                    stdin_data = channel.recv(4096)
                except Exception:
                    pass

            stdin_text = stdin_data.decode("utf-8", errors="replace")

            # 特殊处理 cat > path
            if "cat >" in command:
                path = command.split(">")[-1].strip()
                self.state.files[path] = stdin_text
                channel.send_exit_status(0)
                try:
                    channel.shutdown_write()
                except Exception:
                    pass
                time.sleep(0.05)
                channel.close()
                return

            out, rc = self.state.execute_command(command, stdin_text)
            if out:
                channel.send((out + "\n").encode("utf-8"))
            channel.send_exit_status(rc)
            try:
                channel.shutdown_write()
            except Exception:
                pass
            time.sleep(0.05)
            channel.close()

        def _handle_shell(self, channel):
            channel.send(b"OpenWrt 23.05.5 Mock Shell\r\n# ")
            buf = ""
            while not channel.closed:
                try:
                    data = channel.recv(1024)
                    if not data:
                        break
                    text = data.decode("utf-8", errors="replace")
                    buf += text
                    if "\n" in buf or "\r" in buf:
                        line = buf.strip()
                        buf = ""
                        if line in ("exit", "quit"):
                            break
                        out, rc = self.state.execute_command(line)
                        if out:
                            channel.send((out + "\r\n").encode("utf-8"))
                        channel.send(b"# ")
                except Exception:
                    break
            channel.close()


class MockServerDaemon:
    """管理 Mock SSH 服务的生命周期。"""

    def __init__(self, host="127.0.0.1", port=2222):
        self.host = host
        self.port = port
        self.state = OpenWrtState()
        self.sock = None
        self.thread = None
        self.running = False
        self.host_key = None

    def start(self):
        if paramiko is None:
            raise RuntimeError("Paramiko is required to run the Mock SSH server.")
        key_path = os.path.join(os.path.dirname(__file__), ".mock_host_key")
        if os.path.isfile(key_path):
            try:
                self.host_key = paramiko.RSAKey.from_private_key_file(key_path)
            except Exception:
                self.host_key = paramiko.RSAKey.generate(2048)
                self.host_key.write_private_key_file(key_path)
        else:
            self.host_key = paramiko.RSAKey.generate(2048)
            try:
                pem_io = io.StringIO()
                self.host_key.write_private_key(pem_io)
                with open(key_path, "wb") as f_k:
                    f_k.write(pem_io.getvalue().replace("\r\n", "\n").encode("utf-8"))
            except Exception:
                pass

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(10)
        self.running = True

        self.thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.thread.start()

    def _listen_loop(self):
        while self.running:
            try:
                self.sock.settimeout(1.0)
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()

    def _handle_client(self, conn):
        try:
            transport = paramiko.Transport(conn)
            transport.add_server_key(self.host_key)
            server = MockSSHServer(self.state)
            transport.start_server(server=server)
            chan = transport.accept(20)
            if chan is None:
                return
            while transport.is_active():
                time.sleep(0.5)
        except Exception:
            pass

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 2222
    print(f"[Mock OpenWrt] 正在启动测试服务端于 127.0.0.1:{port} ...")
    server = MockServerDaemon(port=port)
    server.start()
    print("[Mock OpenWrt] 服务端已就绪 (Ctrl+C 退出)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[Mock OpenWrt] 正在停止...")
        server.stop()
