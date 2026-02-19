# RedPivot

高级内网穿透反向代理工具，专为安全研究和红队测试设计，具备四层安全架构。

## 特性

- **四层安全架构** - 传输加密、流量混淆、反调试、内存安全
- **多种代理类型** - TCP、UDP、HTTP、HTTPS、STCP (密钥保护)
- **无盘模式** - 配置仅存内存，支持环境变量配置
- **交互式配置向导** - 快速生成配置文件
- **自动重连** - 指数退避重连机制

## 架构设计

| 层级 | 名称 | 功能 |
|------|------|------|
| Layer 1 | Transport | WebSocket 传输，伪装 HTTPS 流量 |
| Layer 2 | Crypto | XChaCha20-Poly1305 AEAD 加密，会话密钥前向保密 |
| Layer 3 | Countermeasure | 流量填充、时序抖动、多路复用对抗流量分析 |
| Layer 4 | OPSEC | 内存安全、反调试、无盘模式、安全日志 |

## 快速开始

### 构建

```bash
# Windows
powershell scripts/build.ps1

# Linux/macOS
bash scripts/build.sh
```

### 交互式配置生成

```bash
# 服务端配置向导
./bin/redd config init

# 客户端配置向导
./bin/redctl config init
```

### 运行

```bash
# 服务端
./bin/redd -config configs/redd.yaml

# 客户端
./bin/redctl -config configs/redctl.yaml

# 无盘模式
export REDPIVOT_SERVER="wss://server:443/ws"
export REDPIVOT_TOKEN="token"
export REDPIVOT_PROXY_1="tcp:127.0.0.1:22:6022"
./bin/redctl -diskless -env
```

## 命令行参数

### 服务端 (redd)

| 参数 | 说明 |
|------|------|
| `-config <path>` | 配置文件路径 (默认: configs/redd.yaml) |
| `-version` | 显示版本信息 |
| `-help` | 显示帮助信息 |
| `-verify` | 验证配置文件并退出 |
| `config init` | 交互式生成配置文件 |

### 客户端 (redctl)

| 参数 | 说明 |
|------|------|
| `-config <path>` | 配置文件路径 (默认: configs/redctl.yaml) |
| `-version` | 显示版本信息 |
| `-help` | 显示帮助信息 |
| `-verify` | 验证配置文件并退出 |
| `-diskless` | 无盘模式运行 |
| `-env` | 从环境变量读取配置 |
| `-stdin` | 从 stdin 读取配置 (Base64 JSON) |
| `config init` | 交互式生成配置文件 |

---

## 服务端配置 (redd.yaml)

### server - 服务基础配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `bind` | string | `0.0.0.0:443` | 服务监听地址 |
| `domain` | string | - | HTTP/HTTPS 代理使用的域名 |
| `read_timeout` | int | `30` | 读取超时 (秒) |
| `write_timeout` | int | `30` | 写入超时 (秒) |

### auth - 认证配置

| 参数 | 类型 | 说明 |
|------|------|------|
| `method` | string | 认证方式: `token` 或 `mtls` |
| `tokens` | []string | 有效 Token 列表 |

### transport - 传输层配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `type` | string | `websocket` | 传输类型: websocket/quic/grpc |
| `path` | string | `/ws` | WebSocket 路径 |

#### transport.tls - TLS 配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `true` | 是否启用 TLS |
| `cert` | string | - | 证书文件路径 |
| `key` | string | - | 私钥文件路径 |
| `ca` | string | - | CA 证书路径 (可选，用于客户端验证) |

#### transport.websocket - WebSocket 配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `path` | string | `/ws` | WebSocket 路径 |
| `read_buffer_size` | int | `65536` | 读缓冲区大小 |
| `write_buffer_size` | int | `65536` | 写缓冲区大小 |

#### transport.quic - QUIC 配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `max_streams` | int | `1000` | 最大并发流 |
| `max_idle_timeout` | int | `60` | 空闲超时 (秒) |
| `keep_alive_period` | int | `15` | 保活周期 (秒) |

### obfuscation - 流量混淆配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `true` | 是否启用混淆 |
| `padding_probability` | float | `0.3` | 填充概率 (0.0-1.0) |
| `timing_jitter_ms` | int | `50` | 时序抖动 (毫秒) |
| `chunk_min_size` | int | `64` | 分块最小值 (字节) |
| `chunk_max_size` | int | `1500` | 分块最大值 (字节) |

### logging - 日志配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `level` | string | `info` | 日志级别: debug/info/warn/error |
| `format` | string | `json` | 日志格式: json/text |
| `output` | string | `stdout` | 输出: stdout/stderr/文件路径 |

### 完整示例

```yaml
# redd.yaml - 服务端配置示例
server:
  bind: "0.0.0.0:443"
  domain: "pivot.example.com"
  read_timeout: 30
  write_timeout: 30

auth:
  method: "token"
  tokens:
    - "your-secret-token-here"
    - "another-token-for-client2"

transport:
  type: "websocket"
  websocket:
    path: "/ws"
    read_buffer_size: 65536
    write_buffer_size: 65536
  tls:
    enabled: true
    cert: "/etc/redd/cert.pem"
    key: "/etc/redd/key.pem"
  quic:
    max_streams: 1000
    max_idle_timeout: 60
    keep_alive_period: 15

obfuscation:
  enabled: true
  padding_probability: 0.3
  timing_jitter_ms: 50
  chunk_min_size: 64
  chunk_max_size: 1500

logging:
  level: "info"
  format: "json"
  output: "stdout"
```

---

## 客户端配置 (redctl.yaml)

### client - 客户端配置

| 参数 | 类型 | 说明 |
|------|------|------|
| `server` | string | 服务端地址 (如: wss://server:443/ws) |
| `token` | string | 认证 Token |
| `insecure_skip_verify` | bool | 跳过 TLS 证书验证 (默认: false) |

#### client.reconnect - 重连配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `true` | 是否启用自动重连 |
| `max_attempts` | int | `10` | 最大重试次数 |
| `initial_delay` | duration | `1s` | 初始延迟 |
| `max_delay` | duration | `60s` | 最大延迟 |

### proxies - 代理配置

代理配置为列表，每个代理包含以下通用字段：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | ✓ | 代理名称 |
| `type` | string | ✓ | 代理类型: tcp/udp/http/https/stcp |
| `local` | string | ✓ | 本地服务地址 |

#### TCP 代理

```yaml
- name: "ssh"
  type: "tcp"
  local: "127.0.0.1:22"
  remote_port: 6022
```

| 参数 | 类型 | 说明 |
|------|------|------|
| `remote_port` | int | 服务端暴露端口 |

#### UDP 代理

```yaml
- name: "dns"
  type: "udp"
  local: "127.0.0.1:53"
  remote_port: 6053
```

| 参数 | 类型 | 说明 |
|------|------|------|
| `remote_port` | int | 服务端暴露端口 |

#### HTTP 代理

```yaml
- name: "webapp"
  type: "http"
  local: "127.0.0.1:8080"
  subdomain: "myapp"
  # 访问地址: myapp.example.com
```

| 参数 | 类型 | 说明 |
|------|------|------|
| `subdomain` | string | 子域名前缀 |

#### HTTPS 代理

```yaml
- name: "secure-web"
  type: "https"
  local: "127.0.0.1:8443"
  subdomain: "secure"
  cert_file: "/etc/redctl/cert.pem"
  key_file: "/etc/redctl/key.pem"
```

| 参数 | 类型 | 说明 |
|------|------|------|
| `subdomain` | string | 子域名前缀 |
| `cert_file` | string | TLS 证书路径 |
| `key_file` | string | TLS 私钥路径 |

#### STCP 代理 (密钥保护 TCP)

```yaml
- name: "secret-service"
  type: "stcp"
  local: "127.0.0.1:9000"
  remote_port: 6900
  secret_key: "shared-secret-key"
```

| 参数 | 类型 | 说明 |
|------|------|------|
| `remote_port` | int | 服务端暴露端口 |
| `secret_key` | string | 访问密钥 (访问者需要相同密钥) |

### 完整示例

```yaml
# redctl.yaml - 客户端配置示例
client:
  server: "wss://pivot.example.com:443/ws"
  token: "your-secret-token-here"
  insecure_skip_verify: false
  reconnect:
    enabled: true
    max_attempts: 10
    initial_delay: 1s
    max_delay: 60s

proxies:
  # TCP 代理 - 暴露 SSH
  - name: "ssh"
    type: "tcp"
    local: "127.0.0.1:22"
    remote_port: 6022

  # TCP 代理 - 暴露 RDP
  - name: "rdp"
    type: "tcp"
    local: "127.0.0.1:3389"
    remote_port: 6389

  # UDP 代理 - 暴露 DNS
  - name: "dns"
    type: "udp"
    local: "127.0.0.1:53"
    remote_port: 6053

  # HTTP 代理 - Web 应用
  - name: "webapp"
    type: "http"
    local: "127.0.0.1:8080"
    subdomain: "app"
    # 访问地址: app.pivot.example.com

  # HTTPS 代理 - 安全 Web 服务
  - name: "secure-api"
    type: "https"
    local: "127.0.0.1:8443"
    subdomain: "api"
    cert_file: "/etc/redctl/cert.pem"
    key_file: "/etc/redctl/key.pem"
    # 访问地址: api.pivot.example.com

  # STCP 代理 - 密钥保护服务
  - name: "secret-service"
    type: "stcp"
    local: "127.0.0.1:9000"
    remote_port: 6900
    secret_key: "shared-secret-key-only-for-authorized"

logging:
  level: "info"
  format: "text"
  output: "stdout"
```

---

## 无盘模式

无盘模式下配置仅存于内存，不会在磁盘留下痕迹。

### 环境变量

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `REDPIVOT_SERVER` | 服务端地址 | `wss://server:443/ws` |
| `REDPIVOT_TOKEN` | 认证 Token | `your-secret-token` |
| `REDPIVOT_PROXY_N` | 代理定义 | `tcp:127.0.0.1:22:6022` |
| `REDPIVOT_INSECURE` | 跳过 TLS 验证 (任意值) | `1` |

### 代理定义格式

| 类型 | 格式 |
|------|------|
| TCP | `tcp:本地地址:远程端口` |
| UDP | `udp:本地地址:远程端口` |
| HTTP | `http:本地地址:子域名` |
| HTTPS | `https:本地地址:子域名` |
| STCP | `stcp:本地地址:远程端口:密钥` |

示例:
```bash
export REDPIVOT_SERVER="wss://pivot.example.com:443/ws"
export REDPIVOT_TOKEN="your-secret-token"
export REDPIVOT_PROXY_1="tcp:127.0.0.1:22:6022"
export REDPIVOT_PROXY_2="http:127.0.0.1:8080:myapp"
export REDPIVOT_PROXY_3="stcp:127.0.0.1:9000:6900:secret123"

./bin/redctl -diskless -env
```

### Stdin 模式

支持通过 stdin 传入 Base64 编码的 JSON/YAML 配置：

```bash
echo "eyJjbGllbnQiOnsic2VydmVyIjoid3NzOi8vLi4uIn19" | ./bin/redctl -diskless -stdin
```

---

## 项目结构

```
RedPivot/
├── cmd/
│   ├── redd/          # 服务端入口
│   └── redctl/        # 客户端入口
├── internal/
│   ├── auth/          # Token 认证 + 速率限制
│   ├── client/        # 客户端代理处理器
│   ├── config/        # 配置加载
│   │   └── wizard/    # 交互式配置向导
│   ├── countermeasure/# 流量混淆
│   ├── opsec/         # 安全运营 (反调试、无盘模式)
│   ├── proxy/         # 代理实现 (TCP/UDP/HTTP/HTTPS)
│   ├── server/        # 服务端代理管理器
│   ├── transport/     # 传输层 (WebSocket)
│   └── tunnel/        # 隧道核心 (加密、多路复用)
├── pkg/
│   ├── protocol/      # 协议帧定义
│   └── utils/         # 工具函数
├── configs/           # 配置文件示例
└── scripts/           # 构建脚本
```

---

## License

MIT License
