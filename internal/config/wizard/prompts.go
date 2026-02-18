package wizard

import (
	"fmt"
	"strconv"
	"strings"
)

// ReadLine reads a line of text input
func (w *Wizard) ReadLine(prompt, defaultValue string) (string, error) {
	return w.Prompt(prompt, defaultValue)
}

// ReadPassword reads a password (input hidden on supported terminals)
// Note: In basic mode, this works like ReadLine since we can't easily hide input
// without external dependencies
func (w *Wizard) ReadPassword(prompt string) (string, error) {
	w.Print("  %s: ", prompt)
	if !w.scanner.Scan() {
		return "", fmt.Errorf("failed to read input")
	}
	return strings.TrimSpace(w.scanner.Text()), nil
}

// Select displays a menu and returns the selected option
func (w *Wizard) Select(prompt string, options []string, defaultIndex int) (int, error) {
	w.Println("  %s", prompt)
	for i, opt := range options {
		defaultMarker := " "
		if i == defaultIndex {
			defaultMarker = "*"
		}
		w.Println("    %s %d: %s", defaultMarker, i+1, opt)
	}

	input, err := w.Prompt("选择", fmt.Sprintf("%d", defaultIndex+1))
	if err != nil {
		return -1, err
	}

	// Empty input means default
	if input == "" {
		return defaultIndex, nil
	}

	// Parse selection
	selection, err := strconv.Atoi(input)
	if err != nil || selection < 1 || selection > len(options) {
		return -1, fmt.Errorf("无效选择: %s", input)
	}

	return selection - 1, nil
}

// Confirm displays a yes/no prompt
func (w *Wizard) Confirm(prompt string, defaultValue bool) (bool, error) {
	defaultStr := "N"
	if defaultValue {
		defaultStr = "Y"
	}

	input, err := w.Prompt(prompt+" [Y/n]", defaultStr)
	if err != nil {
		return false, err
	}

	input = strings.ToUpper(input)
	if input == "" {
		return defaultValue, nil
	}

	return input == "Y" || input == "YES", nil
}

// ReadInt reads an integer input
func (w *Wizard) ReadInt(prompt string, defaultValue int) (int, error) {
	input, err := w.Prompt(prompt, fmt.Sprintf("%d", defaultValue))
	if err != nil {
		return 0, err
	}

	if input == "" {
		return defaultValue, nil
	}

	value, err := strconv.Atoi(input)
	if err != nil {
		return 0, fmt.Errorf("无效数字: %s", input)
	}

	return value, nil
}

// ReadFloat reads a float input
func (w *Wizard) ReadFloat(prompt string, defaultValue float64) (float64, error) {
	input, err := w.Prompt(prompt, fmt.Sprintf("%.1f", defaultValue))
	if err != nil {
		return 0, err
	}

	if input == "" {
		return defaultValue, nil
	}

	value, err := strconv.ParseFloat(input, 64)
	if err != nil {
		return 0, fmt.Errorf("无效数字: %s", input)
	}

	return value, nil
}

// SelectString displays a menu and returns the selected string
func (w *Wizard) SelectString(prompt string, options []string, defaultIndex int) (string, error) {
	idx, err := w.Select(prompt, options, defaultIndex)
	if err != nil {
		return "", err
	}
	return options[idx], nil
}
