# RedPivot

高级内网穿透反向代理工具，专为安全研究和红队测试设计，具备完整的四层安全架构。

## 架构设计

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Transport (传输层)                             │
│  ├── WebSocket (伪装 HTTPS 流量)                        │
│  ├── QUIC (计划中)                                       │
│  └── gRPC (计划中)                                       │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Crypto (加密层)                                │
│  ├── XChaCha20-Poly1305 (AEAD)                          │
│  ├── 前向保密 (会话密钥)                                 │
│  └── 防重放攻击                                          │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Countermeasure (反制措施)                      │
│  ├── 流量填充 (对抗流量指纹)                             │
│  ├── 时序抖动 (对抗时序分析)                             │
│  ├── 流量分块混淆                                        │
│  └── 多路复用 (减少连接特征)                             │
├─────────────────────────────────────────────────────────┤
│  Layer 4: OPSEC (安全运营)                               │
│  ├── 内存安全 (无明文配置残留)                           │
│  ├── 反调试 / 反沙箱                                     │
│  ├── 磁盘可选 (纯内存运行)                               │
│  └── 日志清理                                            │
└─────────────────────────────────────────────────────────┘
```

## 项目结构

```
redpivot/
├── cmd/
│   ├── redd/              # 服务端
│   └── redctl/            # 客户端
├── internal/
│   ├── tunnel/            # 隧道核心
│   │   ├── crypto.go      # XChaCha20-Poly1305 加密
│   │   └── mux.go         # 连接多路复用
│   ├── proxy/             # 代理实现
│   │   ├── tcp.go         # TCP 代理
│   │   ├── udp.go         # UDP 代理
│   │   └── http.go        # HTTP 代理
│   ├── transport/         # 传输层
│   │   └── websocket.go   # WebSocket 传输
│   ├── countermeasure/    # 反制措施
│   │   └── obfuscator.go  # 流量混淆
│   ├── opsec/             # 安全运营 ⭐ NEW
│   │   ├── memory.go      # 内存安全
│   │   ├── anti_debug.go  # 反调试/反沙箱
│   │   ├── diskless.go    # 无盘模式
│   │   ├── logging.go     # 安全日志
│   │   ├── evasion.go     # 流量规避
│   │   └── opsec.go       # 统一管理
│   ├── config/            # 配置管理
│   └── auth/              # 认证机制
├── pkg/
│   ├── protocol/          # 协议定义
│   └── utils/             # 工具函数
└── configs/               # 配置示例
```

## Layer 4: OPSEC 详细说明

### 1. 内存安全

```go
// 敏感数据自动清零
token := opsec.NewSecureString("secret-token")
defer token.Destroy()  // 使用后自动擦除内存

// 安全字节数组
key := opsec.NewSecureBytes([]byte{...})
defer key.Destroy()
```

特性:
- 敏感配置使用后自动内存清零
- 常量时间比较防止时序攻击
- GC 后强制清除

### 2. 反调试 / 反沙箱

```go
cfg := &opsec.Config{
    EnableAntiDebug:     true,
    DebugDetectionLevel: opsec.DetectionAggressive,
    OnDebugDetected: func() {
        // 检测到调试器时的处理
        os.Exit(1)
    },
}
```

检测方法:
- `/proc/self/status` TracerPid 检测
- 时序分析检测单步调试
- 环境变量检测 (LD_PRELOAD 等)
- 虚拟机特征检测

### 3. 无盘模式

```bash
# 从环境变量读取配置
export REDPIVOT_SERVER="wss://server:443/ws"
export REDPIVOT_TOKEN="your-token"
export REDPIVOT_PROXY_1="tcp:127.0.0.1:22:6022"
./redctl -diskless -env

# 从 stdin 读取 (Base64 JSON)
echo "eyJzZXJ2ZXIiOiIuLi4ifQ==" | ./redctl -diskless -stdin
```

特性:
- 配置只存在于内存
- 支持环境变量配置
- 支持 stdin 管道配置
- 安全删除文件 (多次覆写)

### 4. 安全日志

```go
// 内存日志模式
logger := opsec.NewSecureLogger(opsec.LogModeMemory, 1000)
logger.Info("Connection established")

// 退出时自动清理
defer logger.Purge()  // 擦除所有日志痕迹
```

模式:
- `LogModeNormal` - 正常日志
- `LogModeQuiet` - 静默模式
- `LogModeMemory` - 仅内存日志
- `LogModeSecure` - 加密内存日志

## 快速开始

### 构建

```bash
# Windows
powershell scripts/build.ps1

# Linux/macOS
bash scripts/build.sh
```

### 服务端 (configs/redd.yaml)

```yaml
server:
  bind: "0.0.0.0:443"
  domain: "example.com"

auth:
  method: "token"
  tokens:
    - "your-secret-token"

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

### 客户端 (configs/redctl.yaml)

```yaml
client:
  server: "wss://your-server:443/ws"
  token: "your-secret-token"

proxies:
  - name: "ssh"
    type: "tcp"
    local: "127.0.0.1:22"
    remote_port: 6022
```

### 运行

```bash
# 服务端
./bin/redd -config configs/redd.yaml

# 客户端 (普通模式)
./bin/redctl -config configs/redctl.yaml

# 客户端 (无盘模式)
export REDPIVOT_SERVER="wss://server:443/ws"
export REDPIVOT_TOKEN="token"
./bin/redctl -diskless -env
```

## 安全特性总览

| 层级 | 特性 | 实现 | 目的 |
|------|------|------|------|
| L1 | WebSocket 传输 | ✓ | 伪装 HTTPS 流量 |
| L2 | XChaCha20-Poly1305 | ✓ | AEAD 认证加密 |
| L2 | 会话密钥 | ✓ | 前向保密 |
| L3 | 流量填充 | ✓ | 对抗指纹分析 |
| L3 | 时序抖动 | ✓ | 对抗时序分析 |
| L3 | 多路复用 | ✓ | 减少连接特征 |
| L4 | 内存清零 | ✓ | 无明文残留 |
| L4 | 反调试 | ✓ | 检测分析器 |
| L4 | 反沙箱 | ✓ | 检测虚拟环境 |
| L4 | 无盘模式 | ✓ | 纯内存运行 |
| L4 | 安全日志 | ✓ | 自动清理痕迹 |

## 协议格式

```
+--------+--------+--------+--------+--------+
| Magic  | Ver    | Type   | Flags  | Rsv    |
| 4B     | 1B     | 1B     | 1B     | 1B     |
+--------+--------+--------+--------+--------+
| Stream ID (4B)      | Length (2B)          |
+--------+--------+--------+--------+--------+
| Payload (N bytes)                                 |
+--------------------------------------------------+
```

## 安全建议

1. **始终启用 TLS** - 防止中间人攻击
2. **使用强随机 Token** - 至少 32 字节
3. **启用所有反制措施** - 填充 + 时序抖动
4. **敏感场景使用无盘模式** - 避免磁盘痕迹
5. **定期更换密钥** - 增强前向保密

## License

MIT License - 仅用于授权的安全测试和研究
