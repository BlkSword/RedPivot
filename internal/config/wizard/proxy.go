package wizard

import (
	"fmt"
	"strconv"

	"github.com/redpivot/redpivot/internal/config"
)

// RunProxyWizard runs the interactive proxy configuration wizard
func RunProxyWizard(w *Wizard) (*config.ProxyConfig, error) {
	return RunProxyWizardWithDefaults(w, lenProxyName)
}

// RunProxyWizardWithDefaults runs the proxy wizard with custom default name generator
func RunProxyWizardWithDefaults(w *Wizard, defaultNameFunc func(int) string) (*config.ProxyConfig, error) {
	proxy := &config.ProxyConfig{}
	proxyNum := 1 // Will be set by caller context

	// Proxy name
	name, err := w.ReadLine("代理名称", defaultNameFunc(proxyNum))
	if err != nil {
		return nil, err
	}
	proxy.Name = name

	// Proxy type
	proxyTypes := []string{"tcp", "udp", "http", "https", "stcp"}
	typeDescriptions := []string{
		"TCP 端口转发",
		"UDP 端口转发",
		"HTTP 子域名代理",
		"HTTPS 子域名代理",
		"密钥保护的 TCP",
	}

	w.Println("  代理类型:")
	for i, t := range proxyTypes {
		w.Println("    %d: %s - %s", i+1, t, typeDescriptions[i])
	}

	typeIdx, err := w.Select("选择类型", proxyTypes, 0)
	if err != nil {
		return nil, err
	}
	proxy.Type = proxyTypes[typeIdx]

	// Local address
	local, err := w.ValidateWithRetry(
		"本地地址",
		"127.0.0.1:8080",
		ValidateAddr,
	)
	if err != nil {
		return nil, err
	}
	proxy.Local = local

	// Type-specific configuration
	switch proxy.Type {
	case "tcp", "udp":
		remotePort, err := w.ReadInt("远程端口", 8080)
		if err != nil {
			return nil, err
		}
		proxy.RemotePort = remotePort

	case "stcp":
		remotePort, err := w.ReadInt("远程端口", 8080)
		if err != nil {
			return nil, err
		}
		proxy.RemotePort = remotePort

		secretKey, err := w.ValidateWithRetry(
			"密钥 (回车自动生成)",
			"",
			nil, // Optional, will generate if empty
		)
		if err != nil {
			return nil, err
		}
		if secretKey == "" {
			secretKey = GenerateSecureToken(16)
			w.Println("  ✓ 已生成密钥: %s", secretKey)
		}
		proxy.SecretKey = secretKey

	case "http":
		subdomain, err := w.ReadLine("子域名", "")
		if err != nil {
			return nil, err
		}
		proxy.Subdomain = subdomain

	case "https":
		subdomain, err := w.ReadLine("子域名", "")
		if err != nil {
			return nil, err
		}
		proxy.Subdomain = subdomain

		certFile, err := w.ValidateWithRetry(
			"证书文件路径",
			"",
			ValidateNonEmpty,
		)
		if err != nil {
			return nil, err
		}
		proxy.CertFile = certFile

		keyFile, err := w.ValidateWithRetry(
			"私钥文件路径",
			"",
			ValidateNonEmpty,
		)
		if err != nil {
			return nil, err
		}
		proxy.KeyFile = keyFile
	}

	return proxy, nil
}

// RunSingleProxyWizard runs a standalone proxy wizard (returns config with single proxy)
func RunSingleProxyWizard() (*config.ProxyConfig, error) {
	w := NewWizard()
	w.Println("配置代理")
	w.PrintSeparator()
	return RunProxyWizard(w)
}

// ValidateProxyConfig validates a proxy configuration
func ValidateProxyConfig(proxy *config.ProxyConfig) error {
	if proxy.Name == "" {
		return fmt.Errorf("代理名称不能为空")
	}

	if proxy.Type == "" {
		return fmt.Errorf("代理类型不能为空")
	}

	if proxy.Local == "" {
		return fmt.Errorf("本地地址不能为空")
	}

	switch proxy.Type {
	case "tcp", "udp", "stcp":
		if proxy.RemotePort <= 0 || proxy.RemotePort > 65535 {
			return fmt.Errorf("远程端口无效: %d", proxy.RemotePort)
		}
		if proxy.Type == "stcp" && proxy.SecretKey == "" {
			return fmt.Errorf("STCP 代理需要密钥")
		}
	case "http":
		// Subdomain is optional
	case "https":
		if proxy.CertFile == "" {
			return fmt.Errorf("HTTPS 代理需要证书文件")
		}
		if proxy.KeyFile == "" {
			return fmt.Errorf("HTTPS 代理需要私钥文件")
		}
	default:
		return fmt.Errorf("未知代理类型: %s", proxy.Type)
	}

	return nil
}

// ParseProxyConfig parses a proxy config from string format
// Format: type:local:remote_port_or_subdomain[:secret_key_or_cert_key]
func ParseProxyConfig(s string) (*config.ProxyConfig, error) {
	parts := splitUnquote(s, ":")
	if len(parts) < 3 {
		return nil, fmt.Errorf("无效格式，需要 type:local:port_or_subdomain")
	}

	proxy := &config.ProxyConfig{
		Type:  parts[0],
		Local: parts[1],
	}

	switch parts[0] {
	case "tcp", "udp":
		port, err := strconv.Atoi(parts[2])
		if err != nil {
			return nil, fmt.Errorf("无效端口: %s", parts[2])
		}
		proxy.RemotePort = port
		proxy.Name = fmt.Sprintf("%s-%d", parts[0], port)

	case "stcp":
		port, err := strconv.Atoi(parts[2])
		if err != nil {
			return nil, fmt.Errorf("无效端口: %s", parts[2])
		}
		proxy.RemotePort = port
		if len(parts) > 3 {
			proxy.SecretKey = parts[3]
		}
		proxy.Name = fmt.Sprintf("stcp-%d", port)

	case "http", "https":
		proxy.Subdomain = parts[2]
		proxy.Name = fmt.Sprintf("%s-%s", parts[0], parts[2])
		if parts[0] == "https" && len(parts) > 3 {
			// Format: https:local:subdomain:cert:key
			if len(parts) >= 5 {
				proxy.CertFile = parts[3]
				proxy.KeyFile = parts[4]
			}
		}

	default:
		return nil, fmt.Errorf("未知代理类型: %s", parts[0])
	}

	return proxy, nil
}

// lenProxyName generates a default proxy name
func lenProxyName(num int) string {
	return fmt.Sprintf("proxy-%d", num)
}

// splitUnquote splits a string but preserves quoted sections
func splitUnquote(s string, sep string) []string {
	var result []string
	var current string
	inQuote := false

	for _, r := range s {
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if string(r) == sep && !inQuote {
			result = append(result, current)
			current = ""
			continue
		}
		current += string(r)
	}

	if current != "" {
		result = append(result, current)
	}

	return result
}
