package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Entry struct {
	Timestamp  time.Time `json:"ts"`
	ID         string    `json:"id"`
	Method     string    `json:"method"`
	Target     string    `json:"target"`
	Domain     string    `json:"domain"`
	CredHeader string    `json:"cred_header,omitempty"`
	Status     int       `json:"status,omitempty"`
	DurationMS int64     `json:"duration_ms,omitempty"`
	Blocked    bool      `json:"blocked"`
	BlockedMsg string    `json:"blocked_reason,omitempty"`
	Mode       string    `json:"mode"`
}

type Logger struct {
	mu  sync.Mutex
	out io.Writer
}

func New(path string) (*Logger, error) {
	if path == "" {
		return &Logger{out: os.Stdout}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log %q: %w", path, err)
	}
	return &Logger{out: f}, nil
}

func (l *Logger) Log(e Entry) {
	e.Timestamp = time.Now().UTC()
	if e.ID == "" {
		e.ID = newID()
	}
	b, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out.Write(b)
	l.out.Write([]byte("\n"))
}

func newID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func NewEntry(mode, method, target, domain string) Entry {
	return Entry{
		ID:     newID(),
		Mode:   mode,
		Method: method,
		Target: target,
		Domain: domain,
	}
}

