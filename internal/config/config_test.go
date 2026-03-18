package config

import (
	"os"
	"testing"
)

func TestExpandTemplateStrict_EnvAndKeychain(t *testing.T) {
	t.Setenv("AEGIS_ENV_SECRET", "env-value")
	keychainGet := func(name string) (string, error) {
		if name == "my_token" {
			return "kc-value", nil
		}
		return "", os.ErrNotExist
	}

	got, err := ExpandTemplateStrict(
		"Bearer ${AEGIS_ENV_SECRET}:${keychain:my_token}",
		keychainGet,
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != "Bearer env-value:kc-value" {
		t.Fatalf("unexpected resolved value: %q", got)
	}
}

func TestExpandTemplateStrict_MissingSecretFails(t *testing.T) {
	keychainGet := func(name string) (string, error) {
		return "", os.ErrNotExist
	}

	_, err := ExpandTemplateStrict("${MISSING_ENV}-${keychain:missing}", keychainGet)
	if err == nil {
		t.Fatal("expected error for missing secrets")
	}
}

