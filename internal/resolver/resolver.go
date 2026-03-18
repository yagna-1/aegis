package resolver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrNotFound = errors.New("no aegis.yaml found in current directory or any parent")

type Result struct {
	ConfigPath string
	EnvPath    string
	RootDir    string
}

func Find(startDir, explicitConfig, explicitEnv string) (*Result, error) {

	if explicitConfig != "" {
		abs, err := filepath.Abs(explicitConfig)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(abs); err != nil {
			return nil, fmt.Errorf("config file not found: %s", abs)
		}
		r := &Result{
			ConfigPath: abs,
			RootDir:    filepath.Dir(abs),
		}
		if explicitEnv != "" {
			r.EnvPath, _ = filepath.Abs(explicitEnv)
		} else {
			candidate := filepath.Join(r.RootDir, ".env")
			if _, err := os.Stat(candidate); err == nil {
				r.EnvPath = candidate
			}
		}
		return r, nil
	}

	dir := startDir
	for {
		candidate := filepath.Join(dir, "aegis.yaml")
		if _, err := os.Stat(candidate); err == nil {
			r := &Result{
				ConfigPath: candidate,
				RootDir:    dir,
			}
			envCandidate := filepath.Join(dir, ".env")
			if _, err := os.Stat(envCandidate); err == nil {
				r.EnvPath = envCandidate
			}
			return r, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {

			break
		}
		dir = parent
	}

	return nil, ErrNotFound
}

