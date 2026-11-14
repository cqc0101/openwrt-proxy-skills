#!/usr/bin/env python3
"""Update query parameters without moving them into a node name. Input/output are files."""
import argparse
import os
from pathlib import Path
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def update_query(link, updates):
    if any(ord(c) < 32 or ord(c) == 127 for c in link):
        raise ValueError("control characters are not allowed")
    u = urlsplit(link)
    if u.scheme not in ("vless", "trojan", "hysteria2", "hy2", "tuic") or not u.hostname:
        raise ValueError("unsupported or invalid node URL")
    if u.port is not None and not 1 <= u.port <= 65535:
        raise ValueError("invalid port")
    for key, value in updates.items():
        if not re.fullmatch(r"[A-Za-z0-9_-]+", key) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("invalid query parameter")
    pairs = [(k, v) for k, v in parse_qsl(u.query, keep_blank_values=True) if k not in updates]
    pairs.extend(updates.items())
    return urlunsplit((u.scheme, u.netloc, u.path, urlencode(pairs), u.fragment))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--set", action="append", required=True, metavar="KEY=VALUE")
    a = p.parse_args()
    try:
        updates = {}
        for item in a.set:
            key, sep, value = item.partition("=")
            if not sep:
                raise ValueError("expected KEY=VALUE")
            updates[key] = value
        result = update_query(a.input.read_text(encoding="utf-8").strip(), updates)
        # Never overwrite a source, symlink, or pre-existing output; no URI in stdout/errors.
        fd = os.open(str(a.output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(result + "\n")
    except (OSError, ValueError):
        p.exit(2, "Cannot update node URL; check input, parameters and output path.\n")


if __name__ == "__main__":
    main()
