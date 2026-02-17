# RedPivot

高效反流量分析的内网穿透反向代理工具，使用 Go 语言实现。

## 特性

- **多协议支持**: TCP、UDP、HTTP、HTTPS、STCP（密钥TCP）
- **多传输层**: WebSocket、QUIC（计划中）、gRPC（计划中）
- **反流量分析**:
  - XChaCha20-Poly1305 AEAD 加密
  - 随机流量填充
  - 时序抖动混淆
  - 流量分块混淆
- **高性能**:
  - 连接多路复用（单连接多流）
  - 零拷贝数据转发
  - 异步 I/O
- **易用性**:
  - 类似 frp 的配置方式
  - 热重载配置（计划中）
  - 多平台支持

## 项目结构

```
redpivot/
├── cmd/
│   ├── redd/          # 服务端
│   └── redctl/        # 客户端
├── internal/
│   ├── tunnel/        # 隧道核心（多路复用、加密）
│   ├── proxy/         # 代理实现（TCP/UDP/HTTP）
│   ├── transport/     # 传输层（WebSocket）
│   ├── countermeasure/# 反流量分析
│   ├── config/        # 配置管理
│   └── auth/          # 认证机制
├── pkg/
│   ├── protocol/      # 协议定义
│   └── utils/         # 工具函数
├── configs/           # 配置示例
└── scripts/           # 构建脚本
```

## 快速开始

### 构建

```bash
# Windows
powershell scripts/build.ps1

# Linux/macOS
bash scripts/build.sh
```

### 服务端配置 (configs/redd.yaml)

```yaml
server:
  bind: "0.0.0.0:443"
  domain: "example.com"

auth:
  method: "token"
  tokens:
    - "your-secret-token-here"

transport:
  type: "websocket"
  tls:
    enabled: true
    cert: "/etc/redd/cert.pem"
    key: "/etc/redd/key.pem"

obfuscation:
  enabled: true
  padding_probability: 0.3
  timing_jitter_ms: 50
```

### 客户端配置 (configs/redctl.yaml)

```yaml
client:
  server: "wss://your-server.com:443/ws"
  token: "your-secret-token-here"

proxies:
  - name: "ssh"
    type: "tcp"
    local: "127.0.0.1:22"
    remote_port: 6022

  - name: "web"
    type: "http"
    local: "127.0.0.1:8080"
    subdomain: "myapp"
```

### 运行

```bash
# 服务端
./bin/redd -config configs/redd.yaml

# 客户端
./bin/redctl -config configs/redctl.yaml
```

## 反流量分析特性

| 特性 | 实现 | 目的 |
|------|------|------|
| 强加密 | XChaCha20-Poly1305 | 防止内容泄露 |
| 流量填充 | 随机大小数据块 | 对抗流量指纹分析 |
| 时序抖动 | 随机延迟 0-50ms | 对抗时序分析 |
| 伪装传输 | WebSocket | 混入正常 HTTPS 流量 |
| 多路复用 | 单连接多流 | 减少连接特征 |
| 心跳混淆 | 随机心跳间隔 | 防止心跳指纹识别 |

## 协议格式

```
+----------------+----------------+----------------+
| Magic (4B)     | Version (1B)   | Type (1B)      |
+----------------+----------------+----------------+
| Flags (1B)     | Reserved (1B)  | Stream ID (4B) |
+----------------+----------------+----------------+
| Length (2B)    | Payload (N B)                    |
+----------------+----------------------------------+
```

## 安全建议

1. 始终启用 TLS 加密
2. 使用强随机 Token
3. 定期更换密钥
4. 限制并发连接数
5. 启用速率限制

## License

MIT License
