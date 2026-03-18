package editor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/yagna-1/aegis/internal/vault"
)

func Edit(vaultPath string, key []byte) error {

	var plaintext []byte
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		plaintext = []byte("# Aegis vault — add secrets as KEY=VALUE\n\n")
	} else {
		var err error
		plaintext, err = vault.Open(vaultPath, key)
		if err != nil {
			return fmt.Errorf("opening vault: %w", err)
		}
	}

	tmpDir := os.TempDir()
	tmpFile, err := os.CreateTemp(tmpDir, ".yagna-edit-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	defer func() {
		wipe(tmpPath)
		os.Remove(tmpPath)
	}()

	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return err
	}
	if _, err := tmpFile.Write(plaintext); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	editor := editorBin()
	fmt.Printf("[aegis] opening %s in %s...\n", filepath.Base(vaultPath), editor)
	fmt.Printf("[aegis] plaintext is in %s (will be wiped after you save and close)\n", tmpPath)

	cmd := exec.Command(editor, tmpPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor exited with error: %w", err)
	}

	modified, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("reading modified file: %w", err)
	}

	if err := vault.Seal(vaultPath, modified, key); err != nil {
		return fmt.Errorf("re-encrypting: %w", err)
	}

	fmt.Printf("[aegis] vault saved and encrypted: %s\n", vaultPath)
	fmt.Printf("[aegis] temp file wiped.\n")
	return nil
}

func wipe(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return
	}
	zeros := make([]byte, info.Size())
	f.WriteAt(zeros, 0)
}

func editorBin() string {
	if e := os.Getenv("VISUAL"); e != "" {
		return e
	}
	if e := os.Getenv("EDITOR"); e != "" {
		return e
	}
	switch runtime.GOOS {
	case "windows":
		return "notepad"
	case "darwin":
		return "nano"
	default:
		return "nano"
	}
}

