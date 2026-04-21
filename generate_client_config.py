#!/usr/bin/env python3
"""
generate_client_config.py

Generates a sing-box CLIENT config from a sing-box SERVER config.
Supported protocols : Hysteria2, Shadowsocks, Trojan
Supported transports: plain TCP/UDP, TLS (including Reality / XTLS)
Routing             : Direct bypass for China + private/local addresses
QR output           : ASCII terminal + PNG image per proxy
"""

import argparse
import json
import sys
from copy import deepcopy
from pathlib import Path

import base64
from urllib.parse import urlencode, quote


# ---------------------------------------------------------------------------
# Embedded: share-URI builder
# ---------------------------------------------------------------------------
 

def _b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")
 
 
def _tls_params(tls: dict) -> dict:
    params = {}
    if tls.get("server_name"):
        params["sni"] = tls["server_name"]
    if tls.get("alpn"):
        params["alpn"] = ",".join(tls["alpn"]) if isinstance(tls["alpn"], list) else tls["alpn"]
    reality = tls.get("reality", {})
    if reality.get("enabled"):
        params["security"] = "reality"
        params["pbk"] = reality.get("public_key", "")
        if reality.get("short_id"):
            params["sid"] = reality["short_id"]
        utls = tls.get("utls", {})
        if utls.get("fingerprint"):
            params["fp"] = utls["fingerprint"]
    else:
        params["security"] = "tls"
    return params
 
 
def _shadowsocks_uri(ob: dict) -> str:
    method   = ob.get("method", "2022-blake3-aes-256-gcm")
    password = ob.get("password", "")
    host     = ob.get("server", "")
    port     = ob.get("server_port", 8388)
    tag      = ob.get("tag", "shadowsocks")
 
    userinfo = _b64(f"{method}:{password}")
    uri = f"ss://{userinfo}@{host}:{port}"
 
    extra_params = {}
    plugin = ob.get("plugin")
    if plugin:
        extra_params["plugin"] = plugin
        if ob.get("plugin_opts"):
            extra_params["plugin-opts"] = ob["plugin_opts"]
 
    mux = ob.get("multiplex", {})
    if mux.get("enabled"):
        extra_params["mux"] = mux.get("protocol", "smux")
 
    if extra_params:
        uri += "?" + urlencode(extra_params)
 
    uri += f"#{quote(tag)}"
    return uri
 
 
def _trojan_uri(ob: dict) -> str:
    password = ob.get("password", "")
    host     = ob.get("server", "")
    port     = ob.get("server_port", 443)
    tag      = ob.get("tag", "trojan")
 
    params = {}
    tls = ob.get("tls", {})
    if tls:
        params.update(_tls_params(tls))
 
    flow = ob.get("flow")
    if flow:
        params["flow"] = flow
 
    transport = ob.get("transport", {})
    tp_type = transport.get("type")
    if tp_type and tp_type != "tcp":
        params["type"] = tp_type
        if tp_type == "ws":
            if transport.get("path"):
                params["path"] = transport["path"]
            if transport.get("headers", {}).get("Host"):
                params["host"] = transport["headers"]["Host"]
        elif tp_type == "grpc":
            if transport.get("service_name"):
                params["serviceName"] = transport["service_name"]
    else:
        params.setdefault("type", "tcp")
 
    mux = ob.get("multiplex", {})
    if mux.get("enabled"):
        params["mux"] = mux.get("protocol", "smux")
 
    uri = f"trojan://{quote(password, safe='')}@{host}:{port}"
    if params:
        uri += "?" + urlencode(params)
    uri += f"#{quote(tag)}"
    return uri
 
 
def _hysteria2_uri(ob: dict) -> str:
    password = ob.get("password", "")
    host     = ob.get("server", "")
    port     = ob.get("server_port", 443)
    tag      = ob.get("tag", "hysteria2")
 
    params = {}
    tls = ob.get("tls", {})
    if tls.get("server_name"):
        params["sni"] = tls["server_name"]
    if tls.get("alpn"):
        params["alpn"] = ",".join(tls["alpn"]) if isinstance(tls["alpn"], list) else tls["alpn"]
 
    obfs = ob.get("obfs", {})
    if obfs:
        params["obfs"] = obfs.get("type", "salamander")
        if obfs.get("password"):
            params["obfs-password"] = obfs["password"]
        elif isinstance(obfs, dict) and obfs.get("salamander", {}).get("password"):
            params["obfs-password"] = obfs["salamander"]["password"]
 
    if ob.get("up_mbps"):
        params["upmbps"] = ob["up_mbps"]
    if ob.get("down_mbps"):
        params["downmbps"] = ob["down_mbps"]
 
    uri = f"hy2://{quote(password, safe='')}@{host}:{port}"
    if params:
        uri += "?" + urlencode(params)
    uri += f"#{quote(tag)}"
    return uri
 
 
_BUILDERS = {
    "shadowsocks": _shadowsocks_uri,
    "trojan":      _trojan_uri,
    "hysteria2":   _hysteria2_uri,
}
 
 
def build_uri(outbound: dict) -> str | None:
    """Return a share URI for the outbound, or None if not supported."""
    proto = outbound.get("type", "")
    builder = _BUILDERS.get(proto)
    if builder is None:
        return None
    return builder(outbound)


# ---------------------------------------------------------------------------
# QR code helpers  (requires: pip install "qrcode[pil]")
# ---------------------------------------------------------------------------
 
# Maximum bytes that fit in a version-40 QR at error-correction level L.
# In practice most configs will be under this, but we warn if they're not.
_QR_MAX_BYTES = 2953
 
 
def _make_qr(data: str):
    """Return a configured qrcode.QRCode object encoded with the given string."""
    try:
        import qrcode
    except ImportError:
        raise ImportError(
            "The 'qrcode' package is required for QR output.\n"
            "Install it with:  pip install \"qrcode[pil]\""
        )
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,  # L gives most data capacity
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    return qr
 
 
def _check_qr_size(data: str) -> bool:
    """
    Warn if data exceeds QR capacity. Returns True if the data fits, False otherwise.
    The caller decides whether to abort or attempt encoding anyway.
    """
    size = len(data.encode("utf-8"))
    if size > _QR_MAX_BYTES:
        print(
            f"[warn] Config is {size:,} bytes — exceeds the QR code limit of "
            f"{_QR_MAX_BYTES:,} bytes (version-40 / error-correction L).\n"
            f"[warn] The QR code will likely be unreadable. Consider using --indent 0 "
            f"to produce compact JSON, or sharing the config file directly.",
            file=sys.stderr,
        )
        return False
    return True
 
 
def print_qr_terminal(data: str, label: str = ""):
    """Print a QR code to the terminal as ASCII art."""
    qr = _make_qr(data)
    if label:
        print(f"  {label}")
    qr.print_ascii(invert=True)
    print()
 
 
def save_qr_png(data: str, path, scale: int = 10):
    """Save a QR code as a PNG image (scale param kept for API compat, ignored)."""
    try:
        import qrcode
        from PIL import Image  # noqa: F401 — ensure Pillow is available
    except ImportError as e:
        print(
            f"[warn] PNG skipped — missing dependency: {e}. "
            "Install with:  pip install \"qrcode[pil]\"",
            file=sys.stderr,
        )
        return
    qr = _make_qr(data)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(str(path))
    print(f"  [ok] QR PNG saved: {path}")
 
 
def generate_qr_output(client_cfg: dict, output_dir: str = "", show_terminal: bool = True):
    """
    Encode the full client config JSON as a single QR code.
    Prints ASCII art to the terminal and saves a PNG to output_dir.
    """
    data = json.dumps(client_cfg, ensure_ascii=False, separators=(',', ':'))
 
    _check_qr_size(data)  # warn if too large, but still attempt
 
    sep = "\u2500" * 60
    print(f"\n{sep}")
    print("  sing-box client config QR code")
    print(f"  Size : {len(data.encode()):,} bytes")
    print(sep)
 
    if show_terminal:
        try:
            print_qr_terminal(data, label="Scan to copy and paste config")
        except ImportError as e:
            print(f"[warn] {e}", file=sys.stderr)
 
    if output_dir:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        png_path = output_dir / "qr_client_config.png"
        save_qr_png(data, png_path)
 

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tls_client(server_tls: dict) -> dict:
    """Build a client-side TLS block from the server's inbound TLS block."""
    tls: dict = {"enabled": True}

    # SNI  ── use the server's SNI or server_name field if present
    sni = server_tls.get("server_name") or server_tls.get("sni")
    if sni:
        tls["server_name"] = sni

    # ALPN
    alpn = server_tls.get("alpn")
    if alpn:
        tls["alpn"] = alpn

    # Reality
    reality = server_tls.get("reality")
    if reality:
        tls["reality"] = {
            "enabled": True,
            "public_key": reality.get("public_key", ""),
            "short_id":   reality.get("short_id", ""),
        }
        tls.setdefault("server_name", reality.get("server_name", ""))
        tls["utls"] = {"enabled": True, "fingerprint": "chrome"}

    # XTLS / flow  ── just keep the flow field on the outbound itself (handled per-protocol)

    return tls


# ---------------------------------------------------------------------------
# Per-protocol outbound builders
# ---------------------------------------------------------------------------

def build_hysteria2_outbound(inbound: dict, tag: str) -> dict:
    out: dict = {
        "type":    "hysteria2",
        "tag":     tag,
        "server":  "__SERVER_ADDRESS__",          # placeholder – see note below
        "server_port": inbound.get("listen_port", inbound.get("port", 443)),
    }

    # Password
    users = inbound.get("users", [])
    if users:
        out["password"] = users[0].get("password", "")

    # Up/down bandwidth (optional but recommended)
    up_mbps = inbound.get("up_mbps")
    if up_mbps:
        out["up_mbps"] = inbound["up_mbps"]
    down_mbps = inbound.get("down_mbps")
    if down_mbps:
        out["down_mbps"] = down_mbps

    # Obfuscation (salamander)
    obfs = inbound.get("obfs")
    if obfs:
        out["obfs"] = deepcopy(obfs)

    # TLS (Hysteria2 always uses TLS)
    server_tls = inbound.get("tls", {})
    out["tls"] = _tls_client(server_tls)

    return out


def build_shadowsocks_outbound(inbound: dict, tag: str) -> dict:
    out: dict = {
        "type":        "shadowsocks",
        "tag":         tag,
        "server":      "__SERVER_ADDRESS__",
        "server_port": inbound.get("listen_port", inbound.get("port", 8388)),
        "method":      inbound.get("method", "2022-blake3-aes-256-gcm"),
        "password":    inbound.get("password", ""),
    }

    # Password
    users = inbound.get("users", [])
    if users and users[0].get("password"):
        out["password"] += ":" + users[0].get("password", "")

    # Plugin (e.g. obfs-local / v2ray-plugin) – pass through if present
    plugin = inbound.get("plugin")
    if plugin:
        out["plugin"] = plugin
    plugin_opts = inbound.get("plugin_opts")
    if plugin_opts:
        out["plugin_opts"] = plugin_opts

    # TLS (optional for Shadowsocks)
    server_tls = inbound.get("tls", {})
    if server_tls.get("enabled"):
        out["tls"] = _tls_client(server_tls)

    # Multiplex
    mux = inbound.get("multiplex")
    if mux:
        out["multiplex"] = mux

    return out


def build_trojan_outbound(inbound: dict, tag: str) -> dict:
    users = inbound.get("users", [])
    password = users[0].get("password", "") if users else ""

    out: dict = {
        "type":        "trojan",
        "tag":         tag,
        "server":      "__SERVER_ADDRESS__",
        "server_port": inbound.get("listen_port", inbound.get("port", 443)),
        "password":    password,
    }

    # Transport (WebSocket / gRPC / HTTP) – plain TCP is the default, omit block
    transport = inbound.get("transport")
    if transport and transport.get("type") not in (None, "tcp"):
        out["transport"] = deepcopy(transport)

    # TLS
    server_tls = inbound.get("tls", {})
    if server_tls.get("enabled", True):       # Trojan almost always uses TLS
        out["tls"] = _tls_client(server_tls)

    # Multiplex
    mux = inbound.get("multiplex")
    if mux:
        out["multiplex"] = mux

    return out


PROTOCOL_BUILDERS = {
    "hysteria2":   build_hysteria2_outbound,
    "shadowsocks": build_shadowsocks_outbound,
    "trojan":      build_trojan_outbound,
}


# ---------------------------------------------------------------------------
# DNS block
# ---------------------------------------------------------------------------

def build_dns() -> dict:
    return {
        "servers": [
            {
                "tag": "google",
                "type": "tls",
                "server": "8.8.8.8"
            },
            {
                "tag": "local",
                "type": "udp",
                "server": "223.5.5.5"
            },
            {
                "tag": "remote",
                "type": "fakeip",
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18"
            }
        ],
        "rules": [
            {
                "query_type": [
                    "A",
                    "AAAA"
                ],
                "server": "remote"
            }
        ],
        "independent_cache": True
    }


# ---------------------------------------------------------------------------
# Route block (CN bypass + private bypass)
# ---------------------------------------------------------------------------

def build_route() -> dict:
    return {
        "rules": [
            {
                "action": "sniff"
            },
            {
                "protocol": "dns",
                "action": "hijack-dns"
            },
            {
                "ip_is_private": True,
                "outbound": "direct"
            }
        ],
        "default_domain_resolver": "local",
        "auto_detect_interface": True
    }


# ---------------------------------------------------------------------------
# Inbound (mixed)
# ---------------------------------------------------------------------------

def build_mixed_inbounds(listen_port: int) -> list:
    return [
        {
            "type":         "mixed",
            "tag":          "mixed-in",
            "listen":       "127.0.0.1",
            "listen_port":  listen_port,
        },
    ]


# ---------------------------------------------------------------------------
# Inbound (tun)
# ---------------------------------------------------------------------------

def build_tun_inbounds() -> list:
    return [
        {
            "type": "tun",
            "address": ["172.19.0.1/30","fdfe:dcba:9876::1/126"],
            "auto_route": True,
            "strict_route": True
        }
    ]


# ---------------------------------------------------------------------------
# Core converter
# ---------------------------------------------------------------------------

def convert(server_cfg: dict, server_address: str, use_tun: bool = False, mixed_port: int = 0) -> dict:
    """
    Build a client config from a server config dict.

    :param server_cfg:     Parsed sing-box server JSON.
    :param server_address: The public IP or hostname clients will connect to.
    :returns:              Client config dict (ready to JSON-dump).
    """
    inbounds: list = server_cfg.get("inbounds", [])
    if not inbounds:
        raise ValueError("No inbounds found in server config.")

    outbounds: list = []
    proxy_tags: list[str] = []
    skipped: list[str] = []

    for idx, inbound in enumerate(inbounds):
        proto = inbound.get("type", "").lower()
        builder = PROTOCOL_BUILDERS.get(proto)
        if builder is None:
            skipped.append(proto)
            continue

        tag = inbound.get("tag") or f"{proto}-out-{idx}"
        outbound = builder(inbound, tag)
        # Replace placeholder with real address
        outbound["server"] = server_address
        outbounds.append(outbound)
        proxy_tags.append(tag)

    if not outbounds:
        supported = ", ".join(PROTOCOL_BUILDERS.keys())
        raise ValueError(
            f"No supported inbounds found. Supported protocols: {supported}. "
            f"Found: {', '.join(skipped) or 'none'}."
        )

    if skipped:
        print(f"[warn] Skipped unsupported protocol(s): {', '.join(set(skipped))}", file=sys.stderr)

    # If multiple proxies, wrap in a URLTest selector for auto-selection
    if len(proxy_tags) > 1:
        outbounds.insert(0, {
            "type":     "urltest",
            "tag":      "proxy",
            "outbounds": proxy_tags,
            "url":       "https://www.gstatic.com/generate_204",
            "interval":  "3m",
            "tolerance": 50,
        })

    outbounds += [
        {"type": "direct",  "tag": "direct"},
        # {"type": "block",   "tag": "block"},
        # {"type": "dns",     "tag": "dns-out"},
    ]

    client_cfg: dict = {
        "log":       {"level": "info", "timestamp": True},
        "dns":       build_dns(),
        "inbounds":  build_tun_inbounds() if use_tun else build_mixed_inbounds(mixed_port),
        "outbounds": outbounds,
        "route":     build_route(),
    }

    return client_cfg


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def fetch_public_ip() -> str:
    """Try multiple public IP services in order, return the first success."""
    import urllib.request
    import urllib.error

    services = [
        ("https://api.ipify.org",          lambda r: r.strip()),
        ("https://api4.my-ip.io/ip",       lambda r: r.strip()),
        ("https://checkip.amazonaws.com",  lambda r: r.strip()),
        ("https://icanhazip.com",          lambda r: r.strip()),
    ]

    for url, extract in services:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                ip = extract(resp.read().decode())
                if ip:
                    print(f"[info] Auto-detected public IP: {ip} (via {url})", file=sys.stderr)
                    return ip
        except Exception:
            continue

    raise RuntimeError(
        "Could not auto-detect public IP. "
        "Please pass the server address explicitly as the second argument."
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate a sing-box client config from a server config."
    )
    p.add_argument(
        "server_config",
        help="Path to the sing-box SERVER config JSON file.",
    )
    p.add_argument(
        "server_address",
        nargs="?",
        default=None,
        help="Public IP or hostname clients connect to. "
             "If omitted, the script auto-fetches the public IP of this machine.",
    )
    p.add_argument(
        "--use-tun",
        action="store_true",
        help="Use TUN mode instead of MIXED mode.",
    )
    p.add_argument(
        "--mixed-port",
        type=int,
        default=0,
        help="Listen on the specified port for mixed mode (default: random).",
    )
    p.add_argument(
        "-o", "--output",
        default="client.json",
        help="Output path for the generated client config (default: client.json).",
    )
    p.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indentation spaces (default: 2). Use 0 for compact.",
    )
    p.add_argument(
        "--show-terminal-qr",
        action="store_true",
        help="Generate a QR code for the client config in the terminal.",
    )
    p.add_argument(
        "--qr-dir",
        type=str,
        default="",
        help="Save PNG QR codes to the specified directory.",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()

    server_path = Path(args.server_config)
    if not server_path.exists():
        print(f"[error] Server config not found: {server_path}", file=sys.stderr)
        sys.exit(1)

    with server_path.open("r", encoding="utf-8") as f:
        try:
            server_cfg = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[error] Failed to parse server config: {e}", file=sys.stderr)
            sys.exit(1)

    server_address = args.server_address
    if not server_address:
        try:
            server_address = fetch_public_ip()
        except RuntimeError as e:
            print(f"[error] {e}", file=sys.stderr)
            sys.exit(1)

    try:
        client_cfg = convert(server_cfg, server_address, args.use_tun, args.mixed_port)
    except ValueError as e:
        print(f"[error] {e}", file=sys.stderr)
        sys.exit(1)

    indent = args.indent if args.indent > 0 else None
    output_path = Path(args.output)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(client_cfg, f, indent=indent, ensure_ascii=False)
        f.write("\n")

    print(f"[ok] Client config written to: {output_path}")

    if args.show_terminal_qr or args.qr_dir:
        generate_qr_output(client_cfg, args.qr_dir, args.show_terminal_qr)


if __name__ == "__main__":
    main()