# ShadowsocksSharp 使用说明

本文档介绍 ShadowsocksSharp 的构建、配置与使用方式，包含常用实例与注意事项。

## 项目概述

- 本地代理：单端口自动识别 SOCKS5 / HTTP / HTTPS(CONNECT)
- 上游连接：直连、前置代理（SOCKS5/HTTP）、SIP003 插件
- UDP：SOCKS5 UDP ASSOCIATE + FRAG 分片重组 + AEAD-UDP
- PAC 与 GeoSite：可按规则生成 PAC 并提供本地访问
- 订阅：支持 SIP008 订阅更新

## 运行环境

- Windows 10/11 或 Windows Server
- .NET 10 SDK

## 构建与运行

```bash
# 构建
dotnet build

# 运行（建议从项目根目录）
dotnet run --project src/ShadowsocksSharp.App
```

构建后可执行文件路径示例：

```
src/ShadowsocksSharp.App/bin/Debug/net10.0/ShadowsocksSharp.App.exe
```

## 配置文件位置

配置文件优先级：

1. 当前工作目录下的 `config.json`
2. `%APPDATA%\ShadowsocksSharp\config.json`

## 配置字段说明（常用）

### 全局配置（Config）

- `Configs`: 服务器列表
- `Index`: 当前服务器索引
- `LocalPort`: 本地监听端口
- `TcpListenBacklog`: TCP 监听 backlog（默认 1024）
- `AutoSetSystemProxy`: 启动后是否自动设置系统代理
- `Global`: 是否启用全局代理（true=全局模式，false=PAC 模式）
- `ShareOverLan`: 是否允许局域网访问
- `EnableIPv6`: 是否启用 IPv6 监听
- `ForwardProxy`: 前置代理配置
- `OnlineConfigSource`: 订阅地址列表（SIP008）
- `EnablePerformanceMetrics`: 是否输出性能指标
- `MetricsIntervalSeconds`: 指标输出间隔
- `UdpSessionTimeoutSeconds`: UDP 会话超时
- `MaxUdpSessions`: UDP 会话上限
- `BypassLocal`: 不对本地(intranet)地址使用代理（默认 true）

### 服务器配置（SsServerConfig）

- `Server` / `ServerPort`: 服务器地址与端口
- `Password`: 密码
- `Method`: 加密方法
- `Remarks`: 备注名称
- `Timeout`: 连接超时（秒）
- `Plugin` / `PluginOpts` / `PluginArgs`: SIP003 插件信息
- `SocketSendBuffer` / `SocketReceiveBuffer`: TCP 缓冲区大小
- `ConnectionPoolSize` / `WarmPoolSize`: 连接池参数
- `MaxConnectionsPerSecond`: 每秒新建连接上限

## 基础配置示例

```json
{
  "Configs": [
    {
      "Server": "example.com",
      "ServerPort": 8388,
      "Password": "your-password",
      "Method": "aes-256-gcm",
      "Remarks": "default",
      "Timeout": 300,
      "SocketSendBuffer": 16384,
      "SocketReceiveBuffer": 16384,
      "ConnectionPoolSize": 200,
      "WarmPoolSize": 0,
      "MaxConnectionsPerSecond": 0
    }
  ],
  "Index": 0,
  "LocalPort": 1080,
  "TcpListenBacklog": 1024,
  "AutoSetSystemProxy": true,
  "Global": true,
  "BypassLocal": true,
  "EnablePerformanceMetrics": false,
  "UdpSessionTimeoutSeconds": 300,
  "MaxUdpSessions": 1024,
  "ForwardProxy": {
    "Enabled": false
  }
}
```

## SIP003 插件示例

```json
{
  "Configs": [
    {
      "Server": "example.com",
      "ServerPort": 8388,
      "Password": "your-password",
      "Method": "aes-256-gcm",
      "Plugin": "v2ray-plugin.exe",
      "PluginOpts": "server;tls;host=example.com",
      "PluginArgs": ""
    }
  ],
  "Index": 0,
  "LocalPort": 1080
}
```

说明：
- `Plugin` 为可执行文件路径
- `PluginOpts`/`PluginArgs` 由插件文档定义
- 插件启用后，TCP 上游会忽略前置代理

## 前置代理示例

`ForwardProxy.Type` 为数字枚举：`0 = SOCKS5`，`1 = HTTP`。

```json
{
  "ForwardProxy": {
    "Enabled": true,
    "Type": 0,
    "Host": "127.0.0.1",
    "Port": 1081,
    "TimeoutSeconds": 5,
    "UseAuth": true,
    "Username": "user",
    "Password": "pass"
  }
}
```

说明：
- UDP 仅支持 SOCKS5 前置代理
- HTTP 前置代理仅用于 TCP CONNECT

## PAC 模式配置

- `Global=true`：全局代理模式（启动时设置系统代理为 127.0.0.1:<LocalPort>）
- `Global=false`：PAC 模式
  - `UseOnlinePac=true` 且 `PacUrl` 非空：使用在线 PAC
  - 否则：使用本地 PAC（本地 PAC 地址为 `/pac`）

```json
{
  "Global": false,
  "UseOnlinePac": true,
  "PacUrl": "https://example.com/proxy.pac"
}
```

## 订阅 (SIP008) 示例

```json
{
  "OnlineConfigSource": [
    "https://example.com/subscription"
  ]
}
```

## 命令行用法

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

## 常用操作示例

```bash
# 启动本地代理
dotnet run --project src/ShadowsocksSharp.App

# 选择第 2 个服务器配置
dotnet run --project src/ShadowsocksSharp.App -- -s 1

# 导入 ss:// 链接
dotnet run --project src/ShadowsocksSharp.App -- --import "ss://BASE64..."

# 更新订阅
dotnet run --project src/ShadowsocksSharp.App -- --update-subscriptions

# 测试本地代理
dotnet run --project src/ShadowsocksSharp.App -- --test
```

### 使用 curl 验证代理

```bash
# HTTP 代理
curl -x http://127.0.0.1:1080 https://httpbin.org/ip

# SOCKS5 代理
curl --socks5-hostname 127.0.0.1:1080 https://httpbin.org/ip
```

## 系统代理与 PAC

- 本地监听端口：`127.0.0.1:<LocalPort>`
- 自动协议识别：SOCKS5 / HTTP / HTTPS(CONNECT)
- PAC 地址：
  - `http://127.0.0.1:<LocalPort>/pac`
  - `http://127.0.0.1:<LocalPort>/proxy.pac`
- `AutoSetSystemProxy=true` 时启动即设置系统代理，程序退出时自动关闭

## 项目结构（概览）

```
src/
  ShadowsocksSharp.App            应用入口与 Host
  ShadowsocksSharp.Core           配置/模型/策略
  ShadowsocksSharp.Inbound        SOCKS5/HTTP 入站解析
  ShadowsocksSharp.Outbound       直连/前置代理/插件连接
  ShadowsocksSharp.Services       TCP/UDP/PAC/订阅等服务
  ShadowsocksSharp.Shadowsocks    加解密与协议处理
  ShadowsocksSharp.Transport      Relay/连接池/缓冲
ShadowsocksSharp.Tests            测试
tools/                            工具与插件示例
Docs/                             文档
```

## UDP 支持说明

- 支持 SOCKS5 UDP ASSOCIATE 与 FRAG 分片重组
- UDP 可直连、经 SIP003 插件或 SOCKS5 前置代理
- HTTP 前置代理不支持 UDP

验证建议：
- 使用支持 SOCKS5 UDP 的客户端（如具备 UDP 功能的代理软件）
- 目标可选 DNS（8.8.8.8:53 / 1.1.1.1:53）或自建 UDP Echo 服务

## 日志与诊断

- 日志目录：运行目录下的 `logs`
- `-v` 启用调试日志，`-q` 关闭控制台日志
- `EnablePerformanceMetrics=true` 可输出性能指标

## 常见问题

1) 启动后无法连接  
确认 `config.json` 中的 `Server/ServerPort/Password/Method` 正确，并检查防火墙与端口连通性。

2) UDP 不通  
确认应用支持 SOCKS5 UDP，且未配置 HTTP 前置代理。

3) 插件未生效  
确认 `Plugin` 路径正确，且插件参数满足其文档要求。
