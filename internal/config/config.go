package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Credential struct {
	Header   string `yaml:"header"`
	Template string `yaml:"template"`
}

type DomainBudget struct {
	MaxRequestsPerHour int `yaml:"max_requests_per_hour"`
	LoopThreshold      int `yaml:"loop_threshold"`
}

type InfisicalConfig struct {
	SiteURL            string `yaml:"site_url"`
	ProjectID          string `yaml:"project_id"`
	Environment        string `yaml:"environment"`
	SecretPath         string `yaml:"secret_path"`
	ClientIDSource     string `yaml:"client_id_source"`
	ClientSecretSource string `yaml:"client_secret_source"`
	ClientID           string `yaml:"client_id"`
	ClientSecret       string `yaml:"client_secret"`
}

type Config struct {
	Port        int                     `yaml:"port"`
	AuditLog    string                  `yaml:"audit_log"`
	Allowlist   []string                `yaml:"allowlist"`
	Credentials map[string]Credential   `yaml:"credentials"`
	Budgets     map[string]DomainBudget `yaml:"budgets"`
	Infisical   *InfisicalConfig        `yaml:"infisical"`
}

var envVarRe = regexp.MustCompile(`\$\{([^}:]+)\}`)
var keychainRe = regexp.MustCompile(`\$\{keychain:([^}]+)\}`)

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if cfg.Port == 0 {
		cfg.Port = 8080
	}
	if len(cfg.Allowlist) == 0 {
		return nil, fmt.Errorf("allowlist is empty — at least one domain is required")
	}

	return &cfg, nil
}

func ExpandTemplate(template string, keychainGet func(string) (string, error)) string {
	result := keychainRe.ReplaceAllStringFunc(template, func(m string) string {
		name := m[len("${keychain:") : len(m)-1]
		if keychainGet != nil {
			if val, err := keychainGet(name); err == nil {
				return val
			}
		}
		return ""
	})
	result = envVarRe.ReplaceAllStringFunc(result, func(m string) string {
		return os.Getenv(m[2 : len(m)-1])
	})
	return result
}

func ExpandTemplateStrict(template string, keychainGet func(string) (string, error)) (string, error) {
	var missing []string

	result := keychainRe.ReplaceAllStringFunc(template, func(m string) string {
		name := m[len("${keychain:") : len(m)-1]
		if keychainGet != nil {
			if val, err := keychainGet(name); err == nil && val != "" {
				return val
			}
		}
		missing = append(missing, "keychain:"+name)
		return ""
	})

	result = envVarRe.ReplaceAllStringFunc(result, func(m string) string {
		name := m[2 : len(m)-1]
		val := os.Getenv(name)
		if val == "" {
			missing = append(missing, name)
		}
		return val
	})

	if len(missing) > 0 {
		return "", fmt.Errorf("missing secrets: %s", strings.Join(missing, ", "))
	}
	if strings.TrimSpace(result) == "" {
		return "", errors.New("resolved credential is empty")
	}

	return result, nil
}

