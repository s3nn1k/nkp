// input.go — ввод: чтение мастер-пароля (без эха) и строк.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// Shared reader so piped (non-TTY) input is consumed consistently across calls.
var stdinR = bufio.NewReader(os.Stdin)

func isTTY() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// readPwd reads a secret: via term.ReadPassword on a TTY, or one stdin line
// when piped. Returns []byte so the caller can zero it.
func readPwd(prompt string) ([]byte, error) {
	if !isTTY() {
		line, err := stdinR.ReadString('\n')
		return []byte(strings.TrimRight(line, "\r\n")), err
	}
	fmt.Fprint(os.Stderr, prompt)
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return p, err
}

// readLine reads an echoed line (title/user/selection).
func readLine(prompt string) (string, error) {
	if isTTY() {
		fmt.Fprint(os.Stderr, prompt)
	}
	line, err := stdinR.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}
