package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

const logFile = "data/audit.log"

// Entry represents a single audit log record.
type Entry struct {
	Timestamp string `json:"timestamp"`
	Subject   string `json:"subject"`
	Role      string `json:"role"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
}

// Logger writes structured audit entries to an append-only log file.
type Logger struct {
	mu sync.Mutex
	f  *os.File
}

// New opens or creates the audit log file and returns a Logger.
func New() (*Logger, error) {
	if err := os.MkdirAll("data", 0700); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}

	return &Logger{f: f}, nil
}

// Log writes a single audit entry to the log file as a JSON line.
func (l *Logger) Log(subject, role, method, path string, status int) error {
	entry := Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Subject:   subject,
		Role:      role,
		Method:    method,
		Path:      path,
		Status:    status,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	return json.NewEncoder(l.f).Encode(entry)
}

// Close closes the underlying log file.
func (l *Logger) Close() error {
	return l.f.Close()
}
