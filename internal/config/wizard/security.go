package wizard

import (
	"fmt"
	"time"

	"github.com/redpivot/redpivot/internal/config"
)

// ActiveDefenseConfig represents the active defense configuration
type ActiveDefenseConfig struct {
	FallbackURL      string
	PortKnockEnabled bool
	PortKnockSecret  string
}

// KeyRotationConfig represents the key rotation configuration
type KeyRotationConfig struct {
	Enabled  bool
	Interval time.Duration
}

// HttpAppearanceConfig represents the HTTP appearance configuration
type HttpAppearanceConfig struct {
	Enabled      bool
	UserAgent    string
	Browser      string
	ExtraHeaders map[string]string
	UriTemplate  string
}

// RunSecurityWizard runs the interactive security configuration wizard
func RunSecurityWizard(w *Wizard) (*config.ActiveDefenseSection, error) {
	sec := &config.ActiveDefenseSection{}

	w.PrintHeader("安全高级配置")

	// Active Defense
	w.Println("\n=== 主动防御 ===")
	enableFallback, err := w.Confirm("启用 Fallback URL 重定向", false)
	if err != nil {
		return nil, err
	}
	sec.Fallback.Enabled = enableFallback
	if enableFallback {
		fallbackURL, err := w.ReadLine("Fallback URL (如: https://www.bing.com)", "https://www.bing.com")
		if err != nil {
			return nil, err
		}
		sec.Fallback.TargetURL = fallbackURL
	}

	enablePortKnock, err := w.Confirm("启用端口敲门", false)
	if err != nil {
		return nil, err
	}
	sec.PortKnock.Enabled = enablePortKnock
	if enablePortKnock {
		secret, err := w.ValidateWithRetry(
			"端口敲门密钥 (回车自动生成)",
			"",
			nil,
		)
		if err != nil {
			return nil, err
		}
		if secret == "" {
			secret = GenerateSecureToken(32)
			w.Println("  ✓ 已生成密钥")
		}
		sec.PortKnock.Secret = secret
	}

	return sec, nil
}

// RunClientSecurityWizard runs the client-side security configuration wizard
func RunClientSecurityWizard(w *Wizard) (*config.HttpAppearanceConf, error) {
	sec := &config.HttpAppearanceConf{}

	w.PrintHeader("客户端安全配置")

	// HTTP Appearance
	w.Println("\n=== HTTP 外观伪装 ===")
	enableHttpAppearance, err := w.Confirm("启用 HTTP 外观伪装", false)
	if err != nil {
		return nil, err
	}
	sec.Enabled = enableHttpAppearance

	if enableHttpAppearance {
		useCustomUA, err := w.Confirm("自定义 User-Agent", false)
		if err != nil {
			return nil, err
		}
		if useCustomUA {
			ua, err := w.Prompt("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			if err != nil {
				return nil, err
			}
			sec.UserAgent = ua
		} else {
			// Use browser type for random UA from pool
			browser, err := w.Prompt("浏览器类型 (chrome/firefox/safari/edge/any)", "chrome")
			if err != nil {
				return nil, err
			}
			sec.Browser = browser
		}

		useCustomURI, err := w.Confirm("自定义 URI 模板", false)
		if err != nil {
			return nil, err
		}
		if useCustomURI {
			uri, err := w.ReadLine("URI 模板", "/api/v1/stream")
			if err != nil {
				return nil, err
			}
			sec.UriTemplate = uri
		}

		// Prompt for extra headers
		addHeaders, err := w.Confirm("添加额外 HTTP 头", false)
		if err != nil {
			return nil, err
		}
		if addHeaders {
			sec.ExtraHeaders = make(map[string]string)
			w.Println("  输入额外 HTTP 头 (格式: Header-Name: value)")
			w.Println("  输入空行结束")
			for {
				line, err := w.ReadLine("  头", "")
				if err != nil {
					return nil, err
				}
				if line == "" {
					break
				}
				// Parse header line
				for i, r := range line {
					if r == ':' {
						key := line[:i]
						value := line[i+1:]
						if len(value) > 0 && value[0] == ' ' {
							value = value[1:]
						}
						sec.ExtraHeaders[key] = value
						break
					}
				}
			}
		}
	}

	return sec, nil
}

// PromptKeyRotation prompts for key rotation configuration
func PromptKeyRotation(w *Wizard) (*KeyRotationConfig, error) {
	cfg := &KeyRotationConfig{}

	enabled, err := w.Confirm("启用会话密钥轮换", false)
	if err != nil {
		return nil, err
	}
	cfg.Enabled = enabled

	if enabled {
		intervalStr, err := w.ReadLine("轮换间隔 (如: 30m, 1h, 24h)", "1h")
		if err != nil {
			return nil, err
		}
		interval, err := time.ParseDuration(intervalStr)
		if err != nil {
			return nil, fmt.Errorf("无效的时间间隔: %w", err)
		}
		cfg.Interval = interval
	}

	return cfg, nil
}

// PromptActiveDefense prompts for active defense configuration
func PromptActiveDefense(w *Wizard) (*ActiveDefenseConfig, error) {
	cfg := &ActiveDefenseConfig{}

	w.Println("\n=== 主动防御配置 ===")

	enabled, err := w.Confirm("启用 Fallback URL 重定向", false)
	if err != nil {
		return nil, err
	}
	if enabled {
		url, err := w.ReadLine("Fallback URL", "https://www.bing.com")
		if err != nil {
			return nil, err
		}
		cfg.FallbackURL = url
	}

	enabled, err = w.Confirm("启用端口敲门", false)
	if err != nil {
		return nil, err
	}
	cfg.PortKnockEnabled = enabled

	if enabled {
		secret, err := w.ValidateWithRetry(
			"端口敲门密钥 (回车自动生成)",
			"",
			nil,
		)
		if err != nil {
			return nil, err
		}
		if secret == "" {
			secret = GenerateSecureToken(32)
			w.Println("  ✓ 已生成密钥")
		}
		cfg.PortKnockSecret = secret
	}

	return cfg, nil
}

// PromptHttpAppearance prompts for HTTP appearance configuration
func PromptHttpAppearance(w *Wizard) (*HttpAppearanceConfig, error) {
	cfg := &HttpAppearanceConfig{}

	w.Println("\n=== HTTP 外观伪装 ===")

	enabled, err := w.Confirm("启用 HTTP 外观伪装", false)
	if err != nil {
		return nil, err
	}
	cfg.Enabled = enabled

	if enabled {
		ua, err := w.ReadLine("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		if err != nil {
			return nil, err
		}
		cfg.UserAgent = ua

		uri, err := w.ReadLine("URI 模板", "/api/v1/stream")
		if err != nil {
			return nil, err
		}
		cfg.UriTemplate = uri

		// Prompt for extra headers
		addHeaders, err := w.Confirm("添加额外 HTTP 头", false)
		if err != nil {
			return nil, err
		}
		if addHeaders {
			cfg.ExtraHeaders = make(map[string]string)
			w.Println("  输入额外 HTTP 头 (格式: Header-Name: value)")
			w.Println("  输入空行结束")
			for {
				line, err := w.ReadLine("  头", "")
				if err != nil {
					return nil, err
				}
				if line == "" {
					break
				}
				// Parse header line
				for i, r := range line {
					if r == ':' {
						key := line[:i]
						value := line[i+1:]
						if len(value) > 0 && value[0] == ' ' {
							value = value[1:]
						}
						cfg.ExtraHeaders[key] = value
						break
					}
				}
			}
		}
	}

	return cfg, nil
}
