# RedPivot

高级内网穿透反向代理工具，专为安全研究和红队测试设计，具备四层安全架构。

## 特性

### 核心功能
- **四层安全架构** - 传输加密、流量混淆、反调试、内存安全
- **多种代理类型** - TCP、UDP、HTTP、HTTPS、STCP、**SOCKS5**、**SOCKS5 反向**
- **无盘模式** - 配置仅存内存，支持环境变量配置
- **交互式配置向导** - 快速生成配置文件
- **自动重连** - 指数退避重连机制

### 高级特性
- **SOCKS5 代理** - 正向/反向 SOCKS5 代理，支持红队渗透场景
- **HTTP 外观伪装** - User-Agent 轮换、自定义 Header、流量伪装
- **主动防御** - Fallback URL 重定向、端口敲门 (SPA)
- **密钥轮换** - 定期更换会话密钥，增强前向保密
- **动态心跳** - DGA 算法生成伪随机心跳间隔
- **流量随机化** - 帧填充、时序抖动、大小随机化

## 架构设计

| 层级 | 名称 | 功能 |
|------|------|------|
| Layer 1 | Transport | WebSocket 传输，伪装 HTTPS 流量，HTTP 外观模板 |
| Layer 2 | Crypto | XChaCha20-Poly1305 AEAD 加密，会话密钥轮换 |
| Layer 3 | Countermeasure | 流量填充、时序抖动、DGA 心跳、帧随机化 |
| Layer 4 | OPSEC | 内存安全、反调试、无盘模式、安全日志 |
| Layer 5 | Active Defense | Fallback URL、端口敲门、SPA |

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

### active_defense - 主动防御配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `fallback.enabled` | bool | `false` | 启用 Fallback URL 重定向 |
| `fallback.target_url` | string | - | 重定向目标 URL |
| `fallback.log_only` | bool | `false` | 仅记录不重定向 |
| `port_knock.enabled` | bool | `false` | 启用端口敲门 |
| `port_knock.secret` | string | - | 敲门密钥 (Base64) |
| `port_knock.ttl` | duration | `5m` | 白名单有效期 |
| `port_knock.replay_ttl` | duration | `10m` | 重放保护时间 |

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
| `ca` | string | - | CA 证书路径 (可选) |

#### transport.websocket - WebSocket 配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `path` | string | `/ws` | WebSocket 路径 |
| `read_buffer_size` | int | `65536` | 读缓冲区大小 |
| `write_buffer_size` | int | `65536` | 写缓冲区大小 |

### obfuscation - 流量混淆配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `true` | 是否启用混淆 |
| `padding_probability` | float | `0.3` | 填充概率 (0.0-1.0) |
| `timing_jitter_ms` | int | `50` | 时序抖动 (毫秒) |
| `chunk_min_size` | int | `64` | 分块最小值 (字节) |
| `chunk_max_size` | int | `1500` | 分块最大值 (字节) |

#### obfuscation.key_rotation - 密钥轮换配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `false` | 启用会话密钥轮换 |
| `interval` | duration | `30m` | 轮换间隔 |
| `grace_period` | duration | `5m` | 宽限期 (旧密钥仍可用) |
| `key_history_size` | int | `3` | 密钥历史大小 |
| `rotation_notify` | bool | `true` | 通知对方密钥轮换 |

#### obfuscation.dga_heartbeat - DGA 动态心跳配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `false` | 启用 DGA 心跳 |
| `seed` | string | - | DGA 种子 (Base64) |
| `interval` | duration | `30s` | 基础心跳间隔 |
| `jitter_max` | duration | `10s` | 最大抖动时间 |
| `adaptive` | bool | `false` | 自适应调整 |
| `min_interval` | duration | `15s` | 最小间隔 |
| `max_interval` | duration | `60s` | 最大间隔 |

#### obfuscation.frame_randomization - 帧随机化配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `true` | 启用帧随机化 |
| `min_padding` | int | `4` | 最小填充字节数 |
| `max_padding` | int | `128` | 最大填充字节数 |
| `timing_jitter_min_ms` | int | `0` | 最小时序抖动 |
| `timing_jitter_max_ms` | int | `50` | 最大时序抖动 |
| `size_randomization` | bool | `true` | 启用大小随机化 |

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

# 主动防御配置
active_defense:
  fallback:
    enabled: true
    target_url: "https://www.bing.com"
    log_only: false
  port_knock:
    enabled: true
    secret: "dXNlci1kZWZpbmVkLXNlY3JldC1iYXNlNjQ="
    ttl: 5m
    replay_ttl: 10m

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

obfuscation:
  enabled: true
  padding_probability: 0.3
  timing_jitter_ms: 50
  chunk_min_size: 64
  chunk_max_size: 1500

  # 密钥轮换
  key_rotation:
    enabled: true
    interval: 30m
    grace_period: 5m

  # DGA 动态心跳
  dga_heartbeat:
    enabled: true
    seed: "Z2EtaGVhcnRiZWF0LXNlZWQ="
    interval: 30s
    jitter_max: 10s

  # 帧随机化
  frame_randomization:
    enabled: true
    min_padding: 4
    max_padding: 128

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

#### client.http_appearance - HTTP 外观伪装配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `false` | 启用 HTTP 外观伪装 |
| `user_agent` | string | - | 自定义 User-Agent |
| `browser` | string | `chrome` | 浏览器类型 (chrome/firefox/safari/edge/any) |
| `extra_headers` | map | - | 额外 HTTP 头 |
| `uri_template` | string | - | URI 路径模板 |

### proxies - 代理配置

代理配置为列表，每个代理包含以下通用字段：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | ✓ | 代理名称 |
| `type` | string | ✓ | 代理类型: tcp/udp/http/https/stcp/socks5/rsocks5 |
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
| `secret_key` | string | 访问密钥 |

#### SOCKS5 正向代理

```yaml
- name: "socks5-proxy"
  type: "socks5"
  local: "127.0.0.1:1080"
  # remote_port 可选，留空则由服务端自动分配
  remote_port: 7580
```

| 参数 | 类型 | 说明 |
|------|------|------|
| `remote_port` | int | (可选) 指定远程端口 |

#### SOCKS5 反向代理

```yaml
- name: "rsocks5"
  type: "rsocks5"
  local: "127.0.0.1:1080"
  remote_port: 7580  # 必填
```

| 参数 | 类型 | 说明 |
|------|------|------|
| `remote_port` | int | 远程 SOCKS5 监听端口 |

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

  # HTTP 外观伪装
  http_appearance:
    enabled: true
    browser: "chrome"
    extra_headers:
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      Accept-Language: "en-US,en;q=0.9"
      Cache-Control: "max-age=0"

proxies:
  # TCP 代理 - 暴露 SSH
  - name: "ssh"
    type: "tcp"
    local: "127.0.0.1:22"
    remote_port: 6022

  # SOCKS5 正向代理
  - name: "socks5-proxy"
    type: "socks5"
    local: "127.0.0.1:1080"

  # SOCKS5 反向代理
  - name: "rsocks5"
    type: "rsocks5"
    local: "127.0.0.1:1080"
    remote_port: 7580

logging:
  level: "info"
  format: "text"
  output: "stdout"
```

---

## SOCKS5 代理使用

### 正向 SOCKS5 代理

客户端启动 SOCKS5 代理后，可通过工具连接：

```bash
# 使用 curl
curl --socks5 127.0.0.1:1080 http://internal.example.com

# 使用 Proxychains
proxychains curl http://internal.example.com

# 使用 SOCKS5 客户端
socks5-client 127.0.0.1:1080 internal.example.com:80
```

### 反向 SOCKS5 代理

反向代理在服务端暴露 SOCKS5 端口，服务端可连接回客户端：

```bash
# 在服务端，连接回客户端的 SOCKS5 代理
curl --socks5 server-ip:7580 http://client-local.example.com
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
| SOCKS5 | `socks5:本地地址[:远程端口]` |
| RSOCKS5 | `rsocks5:本地地址:远程端口` |

示例:
```bash
export REDPIVOT_SERVER="wss://pivot.example.com:443/ws"
export REDPIVOT_TOKEN="your-secret-token"
export REDPIVOT_PROXY_1="tcp:127.0.0.1:22:6022"
export REDPIVOT_PROXY_2="socks5:127.0.0.1:1080"
export REDPIVOT_PROXY_3="rsocks5:127.0.0.1:1080:7580"

./bin/redctl -diskless -env
```

---

## 项目结构

```
RedPivot/
├── cmd/
│   ├── redd/          # 服务端入口
│   └── redctl/        # 客户端入口
├── internal/
│   ├── auth/          # 认证 (Token、Fallback、PortKnock)
│   ├── client/        # 客户端代理处理器
│   ├── config/        # 配置加载
│   │   └── wizard/    # 交互式配置向导
│   ├── countermeasure/# 流量混淆 (Obfuscator、DGA、FrameRandom)
│   ├── opsec/         # 安全运营 (反调试、无盘模式)
│   ├── proxy/         # 代理实现 (TCP/UDP/HTTP/HTTPS/SOCKS5)
│   ├── server/        # 服务端代理管理器
│   ├── transport/     # 传输层 (WebSocket、HTTP模板、UA池)
│   └── tunnel/        # 隧道核心 (加密、多路复用、密钥轮换)
├── pkg/
│   ├── protocol/      # 协议帧定义 (包括 SOCKS5)
│   └── utils/         # 工具函数
├── configs/           # 配置文件示例
└── scripts/           # 构建脚本
```

---

## 安全特性

### 传输安全
- XChaCha20-Poly1305 AEAD 加密
- 会话密钥前向保密
- 可选密钥轮换

### 流量保护
- 随机填充对抗流量分析
- 时序抖动对抗时序检测
- DGA 动态心跳对抗模式识别
- HTTP 外观伪装对抗协议检测

### 主动防御
- Fallback URL 重定向防扫描
- 端口敲门 (SPA) 隐藏服务

### OPSEC
- 内存敏感数据自动清零
- 反调试检测
- 无盘模式不留痕迹
- 安全日志自动清理

---

## License

MIT License
