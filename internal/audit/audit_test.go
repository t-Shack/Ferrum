package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
)

func cleanup(t *testing.T) {
	t.Helper()
	os.RemoveAll("data")
}

func TestLog_WritesEntry(t *testing.T) {
	defer cleanup(t)

	logger, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer logger.Close()

	err = logger.Log("admin", "admin", "POST", "/secrets", 201)
	if err != nil {
		t.Fatalf("Log() error: %v", err)
	}

	f, err := os.Open(logFile)
	if err != nil {
		t.Fatalf("open log file error: %v", err)
	}
	defer f.Close()

	var entry Entry
	if err := json.NewDecoder(f).Decode(&entry); err != nil {
		t.Fatalf("decode entry error: %v", err)
	}

	if entry.Subject != "admin" {
		t.Errorf("Subject = %q, want %q", entry.Subject, "admin")
	}
	if entry.Method != "POST" {
		t.Errorf("Method = %q, want %q", entry.Method, "POST")
	}
	if entry.Status != 201 {
		t.Errorf("Status = %d, want %d", entry.Status, 201)
	}
	if entry.Timestamp == "" {
		t.Error("Timestamp is empty")
	}
}

func TestLog_MultipleEntries(t *testing.T) {
	defer cleanup(t)

	logger, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer logger.Close()

	actions := []struct {
		subject string
		method  string
		status  int
	}{
		{"admin", "POST", 201},
		{"reader", "GET", 200},
		{"admin", "DELETE", 200},
	}

	for _, a := range actions {
		if err := logger.Log(a.subject, "admin", a.method, "/secrets", a.status); err != nil {
			t.Fatalf("Log() error: %v", err)
		}
	}

	f, err := os.Open(logFile)
	if err != nil {
		t.Fatalf("open log file error: %v", err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Errorf("line %d: unmarshal error: %v", count+1, err)
		}
		count++
	}

	if count != 3 {
		t.Errorf("log has %d entries, want 3", count)
	}
}

func TestLog_AppendOnly(t *testing.T) {
	defer cleanup(t)

	logger1, err := New()
	if err != nil {
		t.Fatalf("first New() error: %v", err)
	}

	if err := logger1.Log("admin", "admin", "POST", "/secrets", 201); err != nil {
		t.Fatalf("first Log() error: %v", err)
	}
	logger1.Close()

	logger2, err := New()
	if err != nil {
		t.Fatalf("second New() error: %v", err)
	}
	defer logger2.Close()

	if err := logger2.Log("reader", "reader", "GET", "/secrets/key", 200); err != nil {
		t.Fatalf("second Log() error: %v", err)
	}

	f, err := os.Open(logFile)
	if err != nil {
		t.Fatalf("open log file error: %v", err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		count++
	}

	if count != 2 {
		t.Errorf("log has %d entries after two separate loggers, want 2", count)
	}
}
