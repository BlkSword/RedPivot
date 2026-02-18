package wizard

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Validator is a function that validates input
type Validator func(string) error

// ValidatePort validates a port number
func ValidatePort(input string) error {
	port, err := strconv.Atoi(input)
	if err != nil {
		return fmt.Errorf("无效端口号")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("端口必须在 1-65535 范围内")
	}
	return nil
}

// ValidateAddr validates an address (host:port)
func ValidateAddr(input string) error {
	_, _, err := net.SplitHostPort(input)
	if err != nil {
		return fmt.Errorf("无效地址格式，应为 host:port")
	}
	return nil
}

// ValidateURL validates a WebSocket URL
func ValidateURL(input string) error {
	u, err := url.Parse(input)
	if err != nil {
		return fmt.Errorf("无效 URL: %v", err)
	}

	if u.Scheme != "ws" && u.Scheme != "wss" {
		return fmt.Errorf("URL 必须使用 ws:// 或 wss:// 协议")
	}

	if u.Host == "" {
		return fmt.Errorf("URL 必须包含主机名")
	}

	return nil
}

// ValidatePath validates a file path exists
func ValidatePath(input string) error {
	if input == "" {
		return fmt.Errorf("路径不能为空")
	}

	_, err := os.Stat(input)
	if os.IsNotExist(err) {
		return fmt.Errorf("文件不存在: %s", input)
	}
	return nil
}

// ValidatePathOptional validates a file path if provided
func ValidatePathOptional(input string) error {
	if input == "" {
		return nil
	}
	return ValidatePath(input)
}

// ValidateNonEmpty validates input is not empty
func ValidateNonEmpty(input string) error {
	if strings.TrimSpace(input) == "" {
		return fmt.Errorf("此字段不能为空")
	}
	return nil
}

// ValidateToken validates a token
func ValidateToken(input string) error {
	if len(input) < 16 {
		return fmt.Errorf("Token 长度至少 16 字符")
	}
	return nil
}

// ValidateProxyType validates proxy type
func ValidateProxyType(input string) error {
	validTypes := []string{"tcp", "udp", "http", "https", "stcp"}
	for _, t := range validTypes {
		if input == t {
			return nil
		}
	}
	return fmt.Errorf("无效代理类型: %s (有效: tcp, udp, http, https, stcp)", input)
}

// ValidateWithRetry prompts with validation until valid input
func (w *Wizard) ValidateWithRetry(prompt, defaultValue string, validator Validator) (string, error) {
	for {
		input, err := w.Prompt(prompt, defaultValue)
		if err != nil {
			return "", err
		}

		if validator == nil {
			return input, nil
		}

		if err := validator(input); err != nil {
			w.Println("  ✗ %v", err)
			continue
		}

		return input, nil
	}
}
