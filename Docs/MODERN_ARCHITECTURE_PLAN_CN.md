# ShadowsocksSharp 现代化改造方案与落地步骤

本文档基于 shadowsocks-windows 源码对比与当前 ShadowsocksSharp 实现，总结一套更清晰、更直观、更高性能的现代化架构方案，并提供可执行的落地步骤。

## 改造目标

- 架构清晰：按职责拆分，入站解析、出站连接、加密传输、中继完全解耦。
- 现代化：使用 .NET 10 + Generic Host + Pipelines + MemoryPool/ArrayPool。
- 高性能：减少拷贝与分配，降低连接建立与中继成本。
- 功能对齐：覆盖 PAC/UDP/策略/插件/前置代理/订阅/ss:// 导入导出等核心功能。

## 现代化架构（核心组件）

### AppHost（.NET Generic Host）

- 统一配置加载、依赖注入、日志、指标。
- 以 IHostedService 驱动 TCP/UDP/PAC 等服务生命周期。

### Inbound 层

- AutoDetectInbound：读首包识别协议。
- Socks5Inbound / HttpInbound：只做握手与生成 ConnectRequest。
- 统一输出：ConnectRequest(host, port, protocol, extra)。

### Outbound 连接管线

- IOutboundConnector：负责建立“可直接与 SS 服务端通信”的连接。
- ConnectorPipeline：按配置组合 DirectConnector / ForwardProxyConnector / Sip003PluginConnector。
- 规则：插件优先，其次前置代理，否则直连。

### Shadowsocks Transport

- ShadowsocksStream：对 socket 封装 AEAD 流式加解密。
- Encryptor 层保留现有优化，补齐 AEAD-UDP。

### Relay 层

- DuplexRelay：基于 PipeReader/PipeWriter 的双向泵，支持 backpressure。
- 统一 TCP/HTTP/CONNECT 的数据中继。

### 策略层

- IServerSelector + StrategyManager：延迟/失败/吞吐统计，动态选服。
- 在连接建立与中继失败处采集统计。

### 服务层

- UdpRelayService：SOCKS5 UDP ASSOC + 会话 LRU + AEAD-UDP。
- PacService：PAC 生成、PAC HTTP 服务、Geosite 更新。
- SubscriptionService：SIP008/订阅更新。
- SsUrlService：SIP002/legacy ss:// 解析与导入导出。

## 推荐目录结构（清晰、直观）

```
src/
  ShadowsocksSharp.App/            // CLI & host
  ShadowsocksSharp.Core/           // 配置/模型/策略/通用
  ShadowsocksSharp.Transport/      // Socket/Pipelines/Relay
  ShadowsocksSharp.Inbound/        // Socks5/HTTP/AutoDetect
  ShadowsocksSharp.Outbound/       // Direct/Proxy/Plugin/Dialers
  ShadowsocksSharp.Shadowsocks/    // AEAD、SS stream、UDP AEAD
  ShadowsocksSharp.Services/       // PAC/UDP/订阅/更新
  ShadowsocksSharp.Diagnostics/    // 日志、指标、追踪
tests/
```

## 落地步骤（阶段化执行）

当前进度：阶段 5 已完成（核心功能对齐），验证阶段进行中。

### 阶段 1：框架骨架

- [x] 引入 Generic Host：集中管理配置、日志、生命周期。
- [x] 拆出 Core/Transport/Inbound/Outbound/Services 项目结构。
- [x] 迁移现有 AEAD 与基础日志，确保最小可运行。

验收：程序能启动并监听端口，日志与配置加载正常。

### 阶段 2：Inbound/Relay/Outbound 管线

- [x] 实现 AutoDetectInbound + Socks5/HTTP handshake。
- [x] 实现 DuplexRelay（Pipelines）。
- [x] 实现 ConnectorPipeline + DirectConnector。
- [x] 引入 ShadowsocksStream（AEAD 流式加解密）。

验收：SOCKS5/HTTP/CONNECT 可正常代理。

### 阶段 3：插件 + 前置代理（重点）

- [x] SIP003 插件
  - Sip003PluginManager：管理进程、环境变量、端口、重启策略。
  - Sip003PluginConnector：将目标变为 SS_LOCAL_HOST:SS_LOCAL_PORT。
- [x] 前置代理
  - ForwardProxyConnector 支持 SOCKS5/HTTP CONNECT + 认证。
  - 连接管线组合：Plugin? -> Proxy? -> Direct（建议插件优先）。
- [x] 连接池适配
  - 连接池 key 中包含 server + plugin + proxy config，防止误复用。

验收：
- 启用插件可正常建链。
- 前置代理可连接 SS 服务端。
- 插件和代理冲突时有明确日志策略。

### 阶段 4：UDP + PAC + 策略

- [x] UDP Relay + AEAD-UDP（会话 LRU + TTL）。
- [x] PAC 服务 + Geosite 更新 + user-rule 合并。
- [x] 策略选择（HA/负载均衡）。

验收：UDP 应用可代理；PAC 模式可生效；策略自动切换。

### 阶段 5：订阅 + ss:// 导入导出

- [x] SIP002/legacy ss:// 解析与导出。
- [x] 订阅更新服务（SIP008）。

验收：CLI 导入 ss:// 与订阅更新可用。

## 未完成/可选项（非核心验收）

- [x] UDP relay 支持 SIP003 插件与 SOCKS5 前置代理。
- [ ] UDP relay 支持 HTTP 前置代理（可选）。
- [x] SOCKS5 UDP FRAG 分片支持。
- [ ] 实际 UDP 应用经本地 SOCKS5 的全链路验证与文档化。

## 验证与测试状态

- [x] UDP 直连/FRAG/前置代理/插件 集成测试覆盖。
- [ ] 实际 UDP 应用验证（建议：DNS 或本地 UDP echo 程序）。

## 性能优化要点（高性能、现代化）

- Socket.AcceptAsync + Socket.ConnectAsync，避免 TcpClient 额外开销。
- System.IO.Pipelines + MemoryPool<byte> + ArrayPool<byte>，减少拷贝与 GC。
- ValueTask、Span<T>、ReadOnlySequence<byte> 的热路径使用。
- 统一 BufferPool 与 ConnectionPool，降低频繁分配/连接开销。
- RateLimiter 控制每秒新连接数，防止雪崩。
- Logger 改为结构化日志（ILogger），性能开关可配置。
