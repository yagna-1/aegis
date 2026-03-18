package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	header   = "AEGIS-ENCRYPTED-V1"
	FileName = ".yagna"
)

var ErrNotVault = errors.New("not an Aegis vault file")

var ErrNoKey = errors.New("master key not found — run: aegis yagna init")

func KeyName(projectRoot string) string {
	abs, _ := filepath.Abs(projectRoot)
	h := sha256.Sum256([]byte(abs))
	return fmt.Sprintf("project-%x", h[:8])
}

func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	return key, nil
}

func Seal(path string, plaintext []byte, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	content := header + "\n" + encoded + "\n"
	return os.WriteFile(path, []byte(content), 0o600)
}

func Open(path string, key []byte) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	lines := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
	if len(lines) < 2 || lines[0] != header {
		return nil, ErrNotVault
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed — wrong key or tampered file")
	}

	return plaintext, nil
}

func ParseSecrets(plaintext []byte) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(string(plaintext), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])

		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		out[key] = val
	}
	return out
}

func SerializeSecrets(secrets map[string]string) []byte {

	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}

	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	var sb strings.Builder
	sb.WriteString("# Aegis vault — edit via: aegis yagna edit\n")
	sb.WriteString("# This file is encrypted. Do not edit the raw file.\n\n")
	for _, k := range keys {
		sb.WriteString(k + "=" + secrets[k] + "\n")
	}
	return []byte(sb.String())
}

func SetSecret(vaultPath string, key []byte, secretKey, secretVal string) error {
	var secrets map[string]string

	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		secrets = make(map[string]string)
	} else {
		plaintext, err := Open(vaultPath, key)
		if err != nil {
			return err
		}
		secrets = ParseSecrets(plaintext)
	}

	secrets[secretKey] = secretVal
	return Seal(vaultPath, SerializeSecrets(secrets), key)
}

func GetSecret(vaultPath string, key []byte, secretKey string) (string, error) {
	plaintext, err := Open(vaultPath, key)
	if err != nil {
		return "", err
	}
	secrets := ParseSecrets(plaintext)
	val, ok := secrets[secretKey]
	if !ok {
		return "", fmt.Errorf("key %q not found in vault", secretKey)
	}
	return val, nil
}

func ListKeys(vaultPath string, key []byte) ([]string, error) {
	plaintext, err := Open(vaultPath, key)
	if err != nil {
		return nil, err
	}
	secrets := ParseSecrets(plaintext)
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}

	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys, nil
}

func IsVault(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, len(header))
	f.Read(buf)
	return string(buf) == header
}

