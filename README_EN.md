# ShadowsocksSharp

![.NET 10](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows)
![Language](https://img.shields.io/badge/language-C%23-239120?logo=csharp)
![Proxy](https://img.shields.io/badge/proxy-SOCKS5%2FHTTP%2FHTTPS-2F855A)

English | [Chinese](README.md)

A .NET 10 Shadowsocks local proxy that auto-detects SOCKS5 / HTTP / HTTPS (CONNECT) on a single port and supports UDP relay and PAC service.

## Highlights

- Auto-detect SOCKS5 / HTTP / HTTPS (CONNECT)
- AEAD encryption, connection pooling, and high-performance relay
- SIP003 plugin support
- Forward proxy (SOCKS5/HTTP; UDP supports SOCKS5 only)
- UDP relay + SOCKS5 UDP FRAG reassembly
- PAC service and GeoSite rules
- SIP008 subscriptions and ss:// import/export

## Requirements

- Windows 10/11 or Windows Server
- .NET 10 SDK

## Quick start

```bash
dotnet build
dotnet run --project src/ShadowsocksSharp.App
```

Executable path example after build:

```
src/ShadowsocksSharp.App/bin/Debug/net10.0/ShadowsocksSharp.App.exe
```

## Configuration

Config file priority:

1. `config.json` in the current working directory
2. `%APPDATA%\\ShadowsocksSharp\\config.json`

Minimal example:

```json
{
  "Configs": [
    {
      "Server": "example.com",
      "ServerPort": 8388,
      "Password": "your-password",
      "Method": "aes-256-gcm",
      "Remarks": "default"
    }
  ],
  "Index": 0,
  "LocalPort": 1080,
  "TcpListenBacklog": 1024,
  "Global": true,
  "BypassLocal": true
}
```

PAC mode (optional):

```json
{
  "Global": false,
  "UseOnlinePac": true,
  "PacUrl": "https://example.com/proxy.pac"
}
```

For full config fields and more examples, see `Docs/USAGE_GUIDE_CN.md` (Chinese).

## CLI

```bash
ShadowsocksSharp.App.exe [args]

args:
  -h, --help                 show help
  -s, --server N             select server index
  -t, --test                 test local proxy
  --test-ss                  test SS server directly
  -p, --port N               test port (default 1080)
  -u, --url URL              test URL
  --import URL               import ss:// link
  --update-subscriptions     update SIP008 subscriptions
  -q, --quiet                disable console logs
  -v, --verbose              enable debug logs
```

## Project layout

```
src/
  ShadowsocksSharp.App
  ShadowsocksSharp.Core
  ShadowsocksSharp.Diagnostics
  ShadowsocksSharp.Inbound
  ShadowsocksSharp.Outbound
  ShadowsocksSharp.Services
  ShadowsocksSharp.Shadowsocks
  ShadowsocksSharp.Transport
ShadowsocksSharp.Tests/
tools/
Docs/
```

## Docs

- `Docs/USAGE_GUIDE_CN.md` (Chinese)
- `Docs/MODERN_ARCHITECTURE_PLAN_CN.md` (Chinese)

## Tests

```bash
dotnet test
```
