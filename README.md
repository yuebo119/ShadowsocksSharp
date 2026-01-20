# ShadowsocksSharp

![.NET 10](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows)
![Language](https://img.shields.io/badge/language-C%23-239120?logo=csharp)
![Proxy](https://img.shields.io/badge/proxy-SOCKS5%2FHTTP%2FHTTPS-2F855A)

中文 | [English](README_EN.md)

一个基于 .NET 10 的 Shadowsocks 本地代理，单端口自动识别 SOCKS5 / HTTP / HTTPS(CONNECT)，并支持 UDP 中继与 PAC 服务。

## 功能亮点

- 自动识别 SOCKS5 / HTTP / HTTPS(CONNECT)
- AEAD 加密、连接池复用与高性能中继
- SIP003 插件支持
- 前置代理（SOCKS5/HTTP；UDP 仅支持 SOCKS5）
- UDP Relay + SOCKS5 UDP FRAG 重组
- PAC 服务与 GeoSite 规则
- 订阅（SIP008）与 ss:// 导入导出

## 运行环境

- Windows 10/11 或 Windows Server
- .NET 10 SDK

## 快速开始

```bash
dotnet build
dotnet run --project src/ShadowsocksSharp.App
```

构建后可执行文件路径示例：

```
src/ShadowsocksSharp.App/bin/Debug/net10.0/ShadowsocksSharp.App.exe
```

## 配置文件

配置文件优先级：

1. 当前工作目录下的 `config.json`
2. `%APPDATA%\\ShadowsocksSharp\\config.json`

最小示例：

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

PAC 模式（可选）：

```json
{
  "Global": false,
  "UseOnlinePac": true,
  "PacUrl": "https://example.com/proxy.pac"
}
```

更多字段与示例请查看：`Docs/USAGE_GUIDE_CN.md`

## 命令行

```bash
ShadowsocksSharp.App.exe [参数]

参数:
  -h, --help                 显示帮助
  -s, --server N             选择服务器索引
  -t, --test                 测试本地代理
  --test-ss                  直连测试 SS 服务器
  -p, --port N               测试端口（默认 1080）
  -u, --url URL              测试 URL
  --import URL               导入 ss:// 链接
  --update-subscriptions     更新 SIP008 订阅
  -q, --quiet                关闭控制台日志
  -v, --verbose              开启调试日志
```

## 项目结构

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

## 文档

- `Docs/USAGE_GUIDE_CN.md`
- `Docs/MODERN_ARCHITECTURE_PLAN_CN.md`

## 测试

```bash
dotnet test
```
