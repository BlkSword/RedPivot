// Package wizard provides interactive configuration generation
package wizard

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Wizard provides interactive configuration prompts
type Wizard struct {
	scanner *bufio.Scanner
	writer  io.Writer
}

// NewWizard creates a new wizard with default stdin/stdout
func NewWizard() *Wizard {
	return &Wizard{
		scanner: bufio.NewScanner(os.Stdin),
		writer:  os.Stdout,
	}
}

// NewWizardWithIO creates a wizard with custom I/O (for testing)
func NewWizardWithIO(r io.Reader, w io.Writer) *Wizard {
	return &Wizard{
		scanner: bufio.NewScanner(r),
		writer:  w,
	}
}

// Prompt displays a prompt and reads user input
func (w *Wizard) Prompt(prompt, defaultValue string) (string, error) {
	if defaultValue != "" {
		fmt.Fprintf(w.writer, "  %s [%s]: ", prompt, defaultValue)
	} else {
		fmt.Fprintf(w.writer, "  %s: ", prompt)
	}

	if !w.scanner.Scan() {
		return "", fmt.Errorf("failed to read input")
	}

	input := strings.TrimSpace(w.scanner.Text())
	if input == "" {
		return defaultValue, nil
	}
	return input, nil
}

// Print displays a message
func (w *Wizard) Print(format string, args ...interface{}) {
	fmt.Fprintf(w.writer, format, args...)
}

// Println displays a message with newline
func (w *Wizard) Println(format string, args ...interface{}) {
	fmt.Fprintf(w.writer, format+"\n", args...)
}

// PrintSeparator prints a visual separator
func (w *Wizard) PrintSeparator() {
	w.Println("────────────────────────────────────────────────")
}

// PrintHeader prints the wizard header
func (w *Wizard) PrintHeader(title string) {
	w.Println("")
	w.Println("╔═══════════════════════════════════════════════╗")
	fmt.Fprintf(w.writer, "║%s║\n", center(title, 47))
	w.Println("╚═══════════════════════════════════════════════╝")
	w.Println("")
}

// PrintStep prints a step header
func (w *Wizard) PrintStep(step, total int, title string) {
	w.Println("")
	w.Println("[步骤 %d/%d] %s", step, total, title)
}

// Preview displays a configuration preview
func (w *Wizard) Preview(name string, data interface{}) error {
	w.Println("")
	w.PrintSeparator()
	w.Println("配置预览:")
	w.Println("# %s", name)

	yamlData, err := yaml.Marshal(data)
	if err != nil {
		return err
	}

	w.Print("%s", string(yamlData))
	w.PrintSeparator()
	return nil
}

// center centers text within given width
func center(text string, width int) string {
	if len(text) >= width {
		return text[:width]
	}
	padding := (width - len(text)) / 2
	return strings.Repeat(" ", padding) + text + strings.Repeat(" ", width-len(text)-padding)
}
