package keychain

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

func Get(name string) (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return darwinGet(name)
	case "linux":
		return linuxGet(name)
	case "windows":
		return windowsGet(name)
	default:
		return "", fmt.Errorf("keychain not supported on %s", runtime.GOOS)
	}
}

func Set(name, value string) error {
	switch runtime.GOOS {
	case "darwin":
		return darwinSet(name, value)
	case "linux":
		return linuxSet(name, value)
	case "windows":
		return windowsSet(name, value)
	default:
		return fmt.Errorf("keychain not supported on %s", runtime.GOOS)
	}
}

func GetBytes(name string) ([]byte, error) {
	hexStr, err := Get(name)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(hexStr))
}

func SetBytes(name string, data []byte) error {
	return Set(name, hex.EncodeToString(data))
}

func darwinGet(name string) (string, error) {
	out, err := exec.Command("security", "find-generic-password",
		"-s", "aegis", "-a", name, "-w").Output()
	if err != nil {
		return "", fmt.Errorf("keychain: %q not found (run: aegis keychain set %s <value>)", name, name)
	}
	return strings.TrimSpace(string(out)), nil
}

func darwinSet(name, value string) error {
	exec.Command("security", "delete-generic-password", "-s", "aegis", "-a", name).Run()
	cmd := exec.Command("security", "add-generic-password",
		"-s", "aegis", "-a", name, "-w", value)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("keychain set failed: %s", string(out))
	}
	return nil
}

func linuxGet(name string) (string, error) {
	out, err := exec.Command("secret-tool", "lookup", "service", "aegis", "key", name).Output()
	if err != nil {
		return "", fmt.Errorf("keychain: %q not found (install libsecret, run: aegis keychain set %s <value>)", name, name)
	}
	return strings.TrimSpace(string(out)), nil
}

func linuxSet(name, value string) error {
	cmd := exec.Command("secret-tool", "store",
		"--label", "aegis/"+name, "service", "aegis", "key", name)
	cmd.Stdin = strings.NewReader(value)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("secret-tool store failed: %s — is libsecret-tools installed?", string(out))
	}
	return nil
}

func windowsGet(name string) (string, error) {
	script := fmt.Sprintf(
		`(Get-StoredCredential -Target 'aegis/%s').GetNetworkCredential().Password`, name)
	out, err := exec.Command("powershell", "-Command", script).Output()
	if err != nil {
		return "", fmt.Errorf("keychain: %q not found", name)
	}
	val := strings.TrimSpace(string(out))
	if val == "" {
		return "", fmt.Errorf("keychain: %q is empty", name)
	}
	return val, nil
}

func windowsSet(name, value string) error {
	script := fmt.Sprintf(
		`New-StoredCredential -Target 'aegis/%s' -UserName 'aegis' -Password '%s' -Persist LocalMachine`,
		name, strings.ReplaceAll(value, "'", "''"))
	cmd := exec.Command("powershell", "-Command", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("credential manager failed: %s", string(out))
	}
	return nil
}

