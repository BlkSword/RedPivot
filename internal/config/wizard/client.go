package wizard

import (
	"fmt"
	"strings"
	"time"

	"github.com/redpivot/redpivot/internal/config"
)

// RunClientWizard runs the interactive client configuration wizard
func RunClientWizard() (*config.ClientConfig, string, error) {
	w := NewWizard()
	cfg := config.DefaultClientConfig()

	w.PrintHeader("RedPivot 客户端配置向导")

	// Step 1: Server Connection
	w.PrintStep(1, 5, "服务器连接")

	serverURL, err := w.ValidateWithRetry(
		"服务器地址 (例如 wss://server:443/ws)",
		"",
		ValidateURL,
	)
	if err != nil {
		return nil, "", err
	}
	cfg.Client.Server = serverURL

	token, err := w.ValidateWithRetry(
		"认证 Token",
		"",
		ValidateNonEmpty,
	)
	if err != nil {
		return nil, "", err
	}
	cfg.Client.Token = token

	skipTLS, err := w.Confirm("跳过 TLS 验证 (不推荐)", false)
	if err != nil {
		return nil, "", err
	}
	cfg.Client.InsecureSkipVerify = skipTLS

	// Reconnect settings
	w.Println("")
	w.Println("  重连设置:")

	enableReconnect, err := w.Confirm("启用自动重连", true)
	if err != nil {
		return nil, "", err
	}
	cfg.Client.Reconnect.Enabled = enableReconnect

	if enableReconnect {
		maxAttempts, err := w.ReadInt("最大重试次数", cfg.Client.Reconnect.MaxAttempts)
		if err != nil {
			return nil, "", err
		}
		cfg.Client.Reconnect.MaxAttempts = maxAttempts

		initialDelay, err := w.ReadInt("初始延迟/ms", int(cfg.Client.Reconnect.InitialDelay.Milliseconds()))
		if err != nil {
			return nil, "", err
		}
		cfg.Client.Reconnect.InitialDelay = time.Duration(initialDelay) * time.Millisecond

		maxDelay, err := w.ReadInt("最大延迟/ms", int(cfg.Client.Reconnect.MaxDelay.Milliseconds()))
		if err != nil {
			return nil, "", err
		}
		cfg.Client.Reconnect.MaxDelay = time.Duration(maxDelay) * time.Millisecond
	}

	// Step 2: HTTP Appearance
	w.PrintStep(2, 5, "HTTP 外观伪装")

	enableHTTPAppearance, err := w.Confirm("启用 HTTP 外观伪装", false)
	if err != nil {
		return nil, "", err
	}
	cfg.Client.HttpAppearance.Enabled = enableHTTPAppearance

	if enableHTTPAppearance {
		// Browser type selection
		browserTypes := []string{"chrome", "firefox", "safari", "edge", "any"}
		browserDescriptions := []string{
			"Chrome 浏览器",
			"Firefox 浏览器",
			"Safari 浏览器",
			"Edge 浏览器",
			"随机浏览器",
		}
		w.Println("  选择浏览器类型:")
		for i, desc := range browserDescriptions {
			w.Println("    %d: %s", i+1, desc)
		}
		browserIdx, err := w.Select("浏览器", browserTypes, 0)
		if err != nil {
			return nil, "", err
		}
		cfg.Client.HttpAppearance.Browser = browserTypes[browserIdx]

		// Custom User-Agent (optional)
		customUA, err := w.ReadLine("自定义 User-Agent (留空使用浏览器池)", "")
		if err != nil {
			return nil, "", err
		}
		if customUA != "" {
			cfg.Client.HttpAppearance.UserAgent = customUA
		}

		// Custom URI template (optional)
		uriTemplate, err := w.ReadLine("URI 路径模板 (留空使用默认)", "")
		if err != nil {
			return nil, "", err
		}
		if uriTemplate != "" {
			cfg.Client.HttpAppearance.UriTemplate = uriTemplate
		}

		// Extra headers
		w.Println("  额外 HTTP 头 (可选，格式: Name:Value，留空跳过)")
		cfg.Client.HttpAppearance.ExtraHeaders = make(map[string]string)
		for {
			headerName, err := w.ReadLine("  头部名称", "")
			if err != nil {
				return nil, "", err
			}
			if headerName == "" {
				break
			}
			headerValue, err := w.ReadLine("  头部值", "")
			if err != nil {
				return nil, "", err
			}
			cfg.Client.HttpAppearance.ExtraHeaders[headerName] = headerValue
		}
	}

	// Step 3: Proxy Configuration
	w.PrintStep(3, 5, "代理配置")

	proxies := []config.ProxyConfig{}
	proxyNum := 0

	for {
		addProxy, err := w.Confirm("添加代理", len(proxies) == 0)
		if err != nil {
			return nil, "", err
		}

		if !addProxy {
			break
		}

		proxyNum++
		w.Println("")
		w.Println("  ── 代理 #%d ──", proxyNum)

		proxy, err := RunProxyWizard(w)
		if err != nil {
			return nil, "", err
		}

		proxies = append(proxies, *proxy)

		if len(proxies) >= 1 {
			continueAdd, err := w.Confirm("继续添加代理", false)
			if err != nil {
				return nil, "", err
			}
			if !continueAdd {
				break
			}
		}
	}

	cfg.Proxies = proxies

	// Step 4: Logging
	w.PrintStep(4, 5, "日志设置")

	logLevels := []string{"debug", "info", "warn", "error"}
	logLevelIdx, err := w.Select("日志级别", logLevels, 1) // Default to info
	if err != nil {
		return nil, "", err
	}
	cfg.Logging.Level = logLevels[logLevelIdx]

	logFormats := []string{"json", "text"}
	logFormatIdx, err := w.Select("日志格式", logFormats, 1) // Default to text for client
	if err != nil {
		return nil, "", err
	}
	cfg.Logging.Format = logFormats[logFormatIdx]

	output, err := w.ReadLine("输出位置 (stdout 或文件路径)", cfg.Logging.Output)
	if err != nil {
		return nil, "", err
	}
	cfg.Logging.Output = output

	// Step 5: Confirm and Save
	w.PrintStep(5, 5, "确认与保存")

	// Preview
	if err := w.Preview("redctl.yaml", cfg); err != nil {
		return nil, "", err
	}

	confirm, err := w.Confirm("确认保存", true)
	if err != nil {
		return nil, "", err
	}

	if !confirm {
		return nil, "", fmt.Errorf("配置已取消")
	}

	// 直接保存到当前目录
	savePath := "redctl.yaml"

	return cfg, savePath, nil
}

// RunClientWizardWithIO runs the wizard with custom I/O (for testing)
func RunClientWizardWithIO(inputs []string) (*config.ClientConfig, string, error) {
	w := NewWizardWithIO(
		strings.NewReader(strings.Join(inputs, "\n")+"\n"),
		&strings.Builder{},
	)
	cfg := config.DefaultClientConfig()

	w.PrintHeader("RedPivot 客户端配置向导")

	// Step 1: Server
	server, _ := w.ValidateWithRetry("服务器地址", "", ValidateURL)
	cfg.Client.Server = server

	token, _ := w.ValidateWithRetry("Token", "", ValidateNonEmpty)
	cfg.Client.Token = token

	skipTLS, _ := w.Confirm("跳过 TLS 验证", false)
	cfg.Client.InsecureSkipVerify = skipTLS

	// Reconnect
	enableReconnect, _ := w.Confirm("启用自动重连", true)
	cfg.Client.Reconnect.Enabled = enableReconnect

	if enableReconnect {
		maxAttempts, _ := w.ReadInt("最大重试次数", 10)
		cfg.Client.Reconnect.MaxAttempts = maxAttempts
	}

	// Step 2: Proxies
	proxies := []config.ProxyConfig{}
	proxyNum := 0

	for {
		add, _ := w.Confirm("添加代理", len(proxies) == 0)
		if !add {
			break
		}

		proxyNum++
		proxy := config.ProxyConfig{}

		name, _ := w.ReadLine("代理名称", fmt.Sprintf("proxy-%d", proxyNum))
		proxy.Name = name

		proxyType, _ := w.SelectString("代理类型", []string{"tcp", "udp", "http", "https", "stcp"}, 0)
		proxy.Type = proxyType

		local, _ := w.ReadLine("本地地址", "127.0.0.1:8080")
		proxy.Local = local

		switch proxyType {
		case "tcp", "udp", "stcp":
			remotePort, _ := w.ReadInt("远程端口", 8080)
			proxy.RemotePort = remotePort
			if proxyType == "stcp" {
				secretKey, _ := w.ReadLine("密钥", "")
				proxy.SecretKey = secretKey
			}
		case "http", "https":
			subdomain, _ := w.ReadLine("子域名", "")
			proxy.Subdomain = subdomain
			if proxyType == "https" {
				cert, _ := w.ReadLine("证书路径", "")
				proxy.CertFile = cert
				key, _ := w.ReadLine("私钥路径", "")
				proxy.KeyFile = key
			}
		}

		proxies = append(proxies, proxy)

		more, _ := w.Confirm("继续添加", false)
		if !more {
			break
		}
	}

	cfg.Proxies = proxies

	// Step 3: Logging
	logLevel, _ := w.SelectString("日志级别", []string{"debug", "info", "warn", "error"}, 1)
	cfg.Logging.Level = logLevel

	// Step 4: Confirm
	confirm, _ := w.Confirm("确认保存", true)
	if !confirm {
		return nil, "", fmt.Errorf("cancelled")
	}

	savePath, _ := w.ReadLine("保存路径", "configs/redctl.yaml")

	return cfg, savePath, nil
}

// PrintClientSummary prints a summary of the client config
func PrintClientSummary(cfg *config.ClientConfig) {
	w := NewWizard()
	w.Println("")
	w.Println("✓ 客户端配置摘要:")
	w.Println("  服务器: %s", cfg.Client.Server)
	w.Println("  代理数: %d", len(cfg.Proxies))
	w.Println("  重连: %v", cfg.Client.Reconnect.Enabled)
	for _, p := range cfg.Proxies {
		w.Println("    - %s (%s): %s", p.Name, p.Type, p.Local)
	}
}
