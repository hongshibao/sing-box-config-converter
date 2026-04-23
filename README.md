# sing-box-config-converter

Generate a [sing-box](https://sing-box.sagernet.org) **client config** from a **server config**, with optional QR code output.

Supported protocols: `hysteria2`, `shadowsocks`, `trojan`  

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/)

## Quick Start with `uvx`

No installation required — run directly with:

```bash
uvx sing-box-config-converter server.json
```

With QR code support:

```bash
uvx --with "sing-box-config-converter[qr]" sing-box-config-converter server.json
```

## Installation

```bash
uv sync --extra qr
```

The `--extra qr` flag installs `qrcode[pil]` for QR code support. Omit it if you don't need QR output.

## Usage

```bash
uv run sing-box-config-converter <server_config> [server_address] [options]
```

### Arguments

| Argument | Description |
|---|---|
| `server_config` | Path to the sing-box server config JSON |
| `server_address` | Public IP or hostname for clients to connect to. If omitted, auto-detected from the current machine |

### Options

| Option | Default | Description |
|---|---|---|
| `-o, --output` | `client.json` | Output path for the generated client config |
| `--use-tun` | off | Use TUN inbound instead of mixed (SOCKS+HTTP) |
| `--mixed-port` | random | Port for mixed (SOCKS+HTTP) inbound |
| `--show-terminal-qr` | off | Print QR code as ASCII art in the terminal |
| `--qr-dir` | — | Directory to save QR code as a PNG image |

### Examples

Generate a client config (server address auto-detected):
```bash
uv run sing-box-config-converter /etc/sing-box/config.json
```

Specify the server address explicitly:
```bash
uv run sing-box-config-converter /etc/sing-box/config.json 203.0.113.42
```

Use TUN mode and save a QR code image:
```bash
uv run sing-box-config-converter config.json 203.0.113.42 --use-tun --qr-dir ./qr
```

Print a QR code in the terminal:
```bash
uv run sing-box-config-converter config.json --show-terminal-qr
```

If `--show-terminal-qr` QR code is too large to fit in the terminal, try `--qr-dir` to save QR code as a PNG, and use `imgcat` to display it:
```bash
uvx imgcat qr_client_config.png
```

## Output

The generated client config includes:

- **Outbounds** — one per supported inbound in the server config; wrapped in a `urltest` selector when there are multiple
- **DNS** — fakeip for remote, `223.5.5.5` for local/direct
- **Route** — DNS hijack, private IP bypass, sniff
- **Inbound** — `mixed` (SOCKS5+HTTP) on a local port, or `tun` with `auto_route`

## Notes

- QR codes encode the full client config JSON. Large configs may exceed QR capacity; consider sharing the config file directly if the QR is unreadable.