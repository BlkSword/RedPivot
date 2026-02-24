package wizard

import (
	"fmt"
	"strings"
	"time"

	"github.com/redpivot/redpivot/internal/config"
)

// RunServerWizard runs the interactive server configuration wizard
func RunServerWizard() (*config.ServerConfig, string, error) {
	w := NewWizard()
	cfg := config.DefaultServerConfig()

	w.PrintHeader("RedPivot 服务端配置向导")

	// Step 1: Basic Settings
	w.PrintStep(1, 5, "基础设置")

	bind, err := w.ValidateWithRetry(
		"监听地址",
		cfg.Server.Bind,
		ValidateAddr,
	)
	if err != nil {
		return nil, "", err
	}
	cfg.Server.Bind = bind

	domain, err := w.ReadLine("域名 (用于 HTTP 代理)", cfg.Server.Domain)
	if err != nil {
		return nil, "", err
	}
	cfg.Server.Domain = domain

	readTimeout, err := w.ReadInt("读取超时/秒", cfg.Server.ReadTimeout)
	if err != nil {
		return nil, "", err
	}
	cfg.Server.ReadTimeout = readTimeout

	writeTimeout, err := w.ReadInt("写入超时/秒", cfg.Server.WriteTimeout)
	if err != nil {
		return nil, "", err
	}
	cfg.Server.WriteTimeout = writeTimeout

	// Step 2: Authentication
	w.PrintStep(2, 5, "认证设置")

	authMethods := []string{"token", "mtls"}
	authIdx, err := w.Select("认证方式", authMethods, 0)
	if err != nil {
		return nil, "", err
	}
	cfg.Auth.Method = authMethods[authIdx]

	if cfg.Auth.Method == "token" {
		w.Println("  添加认证 Token (回车自动生成)")
		token, err := w.ReadLine("Token", "")
		if err != nil {
			return nil, "", err
		}
		if token == "" {
			token = GenerateSecureToken(32)
			w.Println("  ✓ 已生成 Token: %s...", token[:16])
		}
		cfg.Auth.Tokens = []string{token}
	} else {
		w.Println("  mTLS 认证需要客户端证书")
		caPath, err := w.ValidateWithRetry("CA 证书路径", "", ValidatePathOptional)
		if err != nil {
			return nil, "", err
		}
		cfg.Transport.TLS.CA = caPath
	}

	// Step 3: Transport Settings
	w.PrintStep(3, 5, "传输层设置")

	transportTypes := []string{"websocket", "quic"}
	transportIdx, err := w.Select("传输类型", transportTypes, 0)
	if err != nil {
		return nil, "", err
	}
	cfg.Transport.Type = transportTypes[transportIdx]

	wsPath, err := w.ReadLine("WebSocket 路径", cfg.Transport.WebSocket.Path)
	if err != nil {
		return nil, "", err
	}
	cfg.Transport.Path = wsPath
	cfg.Transport.WebSocket.Path = wsPath

	enableTLS, err := w.Confirm("启用 TLS", true)
	if err != nil {
		return nil, "", err
	}
	cfg.Transport.TLS.Enabled = enableTLS

	if enableTLS {
		certPath, err := w.ValidateWithRetry("证书文件路径", "", ValidateNonEmpty)
		if err != nil {
			return nil, "", err
		}
		cfg.Transport.TLS.Cert = certPath

		keyPath, err := w.ValidateWithRetry("私钥文件路径", "", ValidateNonEmpty)
		if err != nil {
			return nil, "", err
		}
		cfg.Transport.TLS.Key = keyPath
	}

	// Step 4: Obfuscation
	w.PrintStep(4, 7, "流量混淆")

	enableObf, err := w.Confirm("启用流量混淆", true)
	if err != nil {
		return nil, "", err
	}
	cfg.Obfuscation.Enabled = enableObf

	if enableObf {
		paddingProb, err := w.ReadFloat("填充概率", cfg.Obfuscation.PaddingProbability)
		if err != nil {
			return nil, "", err
		}
		cfg.Obfuscation.PaddingProbability = paddingProb

		timingJitter, err := w.ReadInt("时序抖动/ms", cfg.Obfuscation.TimingJitterMs)
		if err != nil {
			return nil, "", err
		}
		cfg.Obfuscation.TimingJitterMs = timingJitter

		w.Println("  分块大小范围")
		chunkMin, err := w.ReadInt("  最小", cfg.Obfuscation.ChunkMinSize)
		if err != nil {
			return nil, "", err
		}
		cfg.Obfuscation.ChunkMinSize = chunkMin

		chunkMax, err := w.ReadInt("  最大", cfg.Obfuscation.ChunkMaxSize)
		if err != nil {
			return nil, "", err
		}
		cfg.Obfuscation.ChunkMaxSize = chunkMax
	}

	// Step 5: Key Rotation
	w.PrintStep(5, 7, "密钥轮换")

	enableKeyRotation, err := w.Confirm("启用会话密钥轮换", false)
	if err != nil {
		return nil, "", err
	}
	cfg.Obfuscation.KeyRotation.Enabled = enableKeyRotation

	if enableKeyRotation {
		intervalStr, err := w.ReadLine("轮换间隔", "30m")
		if err != nil {
			return nil, "", err
		}
		interval, err := time.ParseDuration(intervalStr)
		if err != nil {
			return nil, "", fmt.Errorf("无效的时间间隔格式: %w", err)
		}
		cfg.Obfuscation.KeyRotation.Interval = interval

		graceStr, err := w.ReadLine("宽限期", "5m")
		if err != nil {
			return nil, "", err
		}
		grace, err := time.ParseDuration(graceStr)
		if err != nil {
			return nil, "", fmt.Errorf("无效的宽限期格式: %w", err)
		}
		cfg.Obfuscation.KeyRotation.GracePeriod = grace

		historySize, err := w.ReadInt("密钥历史大小", cfg.Obfuscation.KeyRotation.KeyHistorySize)
		if err != nil {
			return nil, "", err
		}
		cfg.Obfuscation.KeyRotation.KeyHistorySize = historySize

		rotationNotify, err := w.Confirm("通知对方密钥轮换", true)
		if err != nil {
			return nil, "", err
		}
		cfg.Obfuscation.KeyRotation.RotationNotify = rotationNotify
	}

	// Step 6: DGA Heartbeat
	w.PrintStep(6, 7, "动态心跳")

	enableDGA, err := w.Confirm("启用 DGA 动态心跳", false)
	if err != nil {
		return nil, "", err
	}
	cfg.Obfuscation.DGAHeartbeat.Enabled = enableDGA

	if enableDGA {
		seed, err := w.ReadLine("DGA 种子 (Base64, 回车自动生成)", "")
		if err != nil {
			return nil, "", err
		}
		if seed == "" {
			seed = GenerateSecureToken(16)
			w.Println("  ✓ 已生成种子: %s", seed)
		}
		cfg.Obfuscation.DGAHeartbeat.Seed = seed

		intervalStr, err := w.ReadLine("基础心跳间隔", "30s")
		if err != nil {
			return nil, "", err
		}
		interval, err := time.ParseDuration(intervalStr)
		if err != nil {
			return nil, "", fmt.Errorf("无效的时间间隔格式: %w", err)
		}
		cfg.Obfuscation.DGAHeartbeat.Interval = interval

		jitterStr, err := w.ReadLine("最大抖动时间", "10s")
		if err != nil {
			return nil, "", err
		}
		jitter, err := time.ParseDuration(jitterStr)
		if err != nil {
			return nil, "", fmt.Errorf("无效的抖动时间格式: %w", err)
		}
		cfg.Obfuscation.DGAHeartbeat.JitterMax = jitter

		adaptive, err := w.Confirm("自适应调整", false)
		if err != nil {
			return nil, "", err
		}
		cfg.Obfuscation.DGAHeartbeat.Adaptive = adaptive

		if adaptive {
			minStr, err := w.ReadLine("最小间隔", "15s")
			if err != nil {
				return nil, "", err
			}
			min, err := time.ParseDuration(minStr)
			if err != nil {
				return nil, "", fmt.Errorf("无效的时间间隔格式: %w", err)
			}
			cfg.Obfuscation.DGAHeartbeat.MinInterval = min

			maxStr, err := w.ReadLine("最大间隔", "60s")
			if err != nil {
				return nil, "", err
			}
			max, err := time.ParseDuration(maxStr)
			if err != nil {
				return nil, "", fmt.Errorf("无效的时间间隔格式: %w", err)
			}
			cfg.Obfuscation.DGAHeartbeat.MaxInterval = max
		}
	}

	// Step 7: Frame Randomization
	w.PrintStep(7, 7, "帧随机化")

	enableFrameRand, err := w.Confirm("启用帧随机化", true)
	if err != nil {
		return nil, "", err
	}
	cfg.Obfuscation.FrameRandomization.Enabled = enableFrameRand

	if enableFrameRand {
		minPadding, err := w.ReadInt("最小填充字节数", cfg.Obfuscation.FrameRandomization.MinPadding)
		if err != nil {
			return nil, "", err
		}
		cfg.Obfuscation.FrameRandomization.MinPadding = minPadding

		maxPadding, err := w.ReadInt("最大填充字节数", cfg.Obfuscation.FrameRandomization.MaxPadding)
		if err != nil {
			return nil, "", err
		}
		cfg.Obfuscation.FrameRandomization.MaxPadding = maxPadding

		w.Println("  时序抖动范围 (毫秒)")
		timingMin, err := w.ReadInt("  最小", cfg.Obfuscation.FrameRandomization.TimingJitterMinMs)
		if err != nil {
			return nil, "", err
		}
		cfg.Obfuscation.FrameRandomization.TimingJitterMinMs = timingMin

		timingMax, err := w.ReadInt("  最大", cfg.Obfuscation.FrameRandomization.TimingJitterMaxMs)
		if err != nil {
			return nil, "", err
		}
		cfg.Obfuscation.FrameRandomization.TimingJitterMaxMs = timingMax

		sizeRand, err := w.Confirm("启用大小随机化", true)
		if err != nil {
			return nil, "", err
		}
		cfg.Obfuscation.FrameRandomization.SizeRandomization = sizeRand
	}

	// Step 8: Active Defense
	w.PrintStep(8, 9, "主动防御")

	enableActiveDefense, err := w.Confirm("启用主动防御", false)
	if err != nil {
		return nil, "", err
	}

	if enableActiveDefense {
		// Fallback URL
		enableFallback, err := w.Confirm("启用 Fallback URL 重定向", false)
		if err != nil {
			return nil, "", err
		}
		cfg.ActiveDefense.Fallback.Enabled = enableFallback

		if enableFallback {
			fallbackURL, err := w.ReadLine("重定向目标 URL", "https://www.bing.com")
			if err != nil {
				return nil, "", err
			}
			cfg.ActiveDefense.Fallback.TargetURL = fallbackURL

			logOnly, err := w.Confirm("仅记录不重定向", false)
			if err != nil {
				return nil, "", err
			}
			cfg.ActiveDefense.Fallback.LogOnly = logOnly
		}

		// Port Knocking
		enablePortKnock, err := w.Confirm("启用端口敲门 (SPA)", false)
		if err != nil {
			return nil, "", err
		}
		cfg.ActiveDefense.PortKnock.Enabled = enablePortKnock

		if enablePortKnock {
			secret, err := w.ReadLine("敲门密钥 (Base64, 回车自动生成)", "")
			if err != nil {
				return nil, "", err
			}
			if secret == "" {
				secret = GenerateSecureToken(32)
				w.Println("  ✓ 已生成密钥: %s", secret)
			}
			cfg.ActiveDefense.PortKnock.Secret = secret

			ttlStr, err := w.ReadLine("白名单有效期", "5m")
			if err != nil {
				return nil, "", err
			}
			ttl, err := time.ParseDuration(ttlStr)
			if err != nil {
				return nil, "", fmt.Errorf("无效的时间格式: %w", err)
			}
			cfg.ActiveDefense.PortKnock.TTL = ttl

			replayTTLStr, err := w.ReadLine("重放保护时间", "10m")
			if err != nil {
				return nil, "", err
			}
			replayTTL, err := time.ParseDuration(replayTTLStr)
			if err != nil {
				return nil, "", fmt.Errorf("无效的时间格式: %w", err)
			}
			cfg.ActiveDefense.PortKnock.ReplayTTL = replayTTL
		}
	}

	// Step 9: Logging
	w.PrintStep(9, 9, "日志设置")

	logLevels := []string{"debug", "info", "warn", "error"}
	logLevelIdx, err := w.Select("日志级别", logLevels, 1) // Default to info
	if err != nil {
		return nil, "", err
	}
	cfg.Logging.Level = logLevels[logLevelIdx]

	logFormats := []string{"json", "text"}
	logFormatIdx, err := w.Select("日志格式", logFormats, 0) // Default to json
	if err != nil {
		return nil, "", err
	}
	cfg.Logging.Format = logFormats[logFormatIdx]

	output, err := w.ReadLine("输出位置 (stdout 或文件路径)", cfg.Logging.Output)
	if err != nil {
		return nil, "", err
	}
	cfg.Logging.Output = output

	// Preview
	if err := w.Preview("redd.yaml", cfg); err != nil {
		return nil, "", err
	}

	// Confirm and save
	confirm, err := w.Confirm("确认保存", true)
	if err != nil {
		return nil, "", err
	}

	if !confirm {
		return nil, "", fmt.Errorf("配置已取消")
	}

	// 直接保存到当前目录
	savePath := "redd.yaml"

	return cfg, savePath, nil
}

// RunServerWizardWithIO runs the wizard with custom I/O (for testing)
func RunServerWizardWithIO(inputs []string) (*config.ServerConfig, string, error) {
	w := NewWizardWithIO(
		strings.NewReader(strings.Join(inputs, "\n")+"\n"),
		&strings.Builder{},
	)
	cfg := config.DefaultServerConfig()

	// Simplified wizard for testing
	w.PrintHeader("RedPivot 服务端配置向导")

	// Step 1: Basic
	bind, _ := w.Prompt("监听地址", cfg.Server.Bind)
	cfg.Server.Bind = bind

	domain, _ := w.ReadLine("域名", cfg.Server.Domain)
	cfg.Server.Domain = domain

	// Step 2: Auth
	authMethod, _ := w.SelectString("认证方式", []string{"token", "mtls"}, 0)
	cfg.Auth.Method = authMethod

	if authMethod == "token" {
		token, _ := w.ReadLine("Token", "")
		if token == "" {
			token = GenerateSecureToken(32)
		}
		cfg.Auth.Tokens = []string{token}
	}

	// Step 3: Transport
	transportType, _ := w.SelectString("传输类型", []string{"websocket", "quic"}, 0)
	cfg.Transport.Type = transportType

	wsPath, _ := w.ReadLine("WebSocket 路径", "/ws")
	cfg.Transport.Path = wsPath
	cfg.Transport.WebSocket.Path = wsPath

	enableTLS, _ := w.Confirm("启用 TLS", true)
	cfg.Transport.TLS.Enabled = enableTLS

	if enableTLS {
		cert, _ := w.ReadLine("证书路径", "")
		cfg.Transport.TLS.Cert = cert
		key, _ := w.ReadLine("私钥路径", "")
		cfg.Transport.TLS.Key = key
	}

	// Step 4: Obfuscation
	enableObf, _ := w.Confirm("启用流量混淆", true)
	cfg.Obfuscation.Enabled = enableObf

	// Step 5: Logging
	logLevel, _ := w.SelectString("日志级别", []string{"debug", "info", "warn", "error"}, 1)
	cfg.Logging.Level = logLevel

	logFormat, _ := w.SelectString("日志格式", []string{"json", "text"}, 0)
	cfg.Logging.Format = logFormat

	// Confirm
	confirm, _ := w.Confirm("确认保存", true)
	if !confirm {
		return nil, "", fmt.Errorf("cancelled")
	}

	savePath, _ := w.ReadLine("保存路径", "configs/redd.yaml")

	return cfg, savePath, nil
}

// PrintServerSummary prints a summary of the server config
func PrintServerSummary(cfg *config.ServerConfig) {
	w := NewWizard()
	w.Println("")
	w.Println("✓ 服务端配置摘要:")
	w.Println("  监听: %s", cfg.Server.Bind)
	w.Println("  TLS: %v", cfg.Transport.TLS.Enabled)
	w.Println("  认证: %s", cfg.Auth.Method)
	w.Println("  混淆: %v", cfg.Obfuscation.Enabled)
	if len(cfg.Auth.Tokens) > 0 {
		w.Println("  Token: %s...", cfg.Auth.Tokens[0][:min(16, len(cfg.Auth.Tokens[0]))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Ensure ServerConfig implements validation
var _ = time.Duration(0) // Just to import time
