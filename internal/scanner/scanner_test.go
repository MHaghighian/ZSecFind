package scanner

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestScanDirParallel(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vulnerable-app")
	serial, err := ScanDir(root, ScanOptions{Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	parallel, err := ScanDir(root, ScanOptions{Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(serial) != len(parallel) {
		t.Fatalf("worker mismatch: serial=%d parallel=%d", len(serial), len(parallel))
	}

	serialTotal := 0
	for _, r := range serial {
		serialTotal += r.TotalFindings()
	}
	parallelTotal := 0
	for _, r := range parallel {
		parallelTotal += r.TotalFindings()
	}
	if serialTotal != parallelTotal {
		t.Fatalf("findings mismatch: serial=%d parallel=%d", serialTotal, parallelTotal)
	}
}

func TestScanFileFindsSecrets(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "vulnerable-app", "assets", "js", "config.js")
	r, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Secret) == 0 {
		t.Fatal("expected secrets in config.js")
	}
	joined := ""
	for _, s := range r.Secret {
		joined += s.Value + "\n"
	}
	for _, needle := range []string{"AKIA", "ghp_", "hooks.slack.com", "sk_live_"} {
		if !strings.Contains(joined, needle) {
			t.Errorf("expected secret containing %q", needle)
		}
	}
}

func TestScanDirVulnerableApp(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "vulnerable-app")
	rs, err := ScanDir(root, ScanOptions{Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) == 0 {
		t.Fatal("expected findings from vulnerable-app")
	}
	totalSecrets := 0
	for _, r := range rs {
		totalSecrets += len(r.Secret)
	}
	if totalSecrets < 5 {
		t.Fatalf("expected multiple secrets, got %d across %d files", totalSecrets, len(rs))
	}
}

func TestScanFileOptsOnlySecrets(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "vulnerable-app", "assets", "js", "config.js")
	r, err := ScanFileOpts(path, ScanOptions{Categories: []string{"secret", "jwt"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Secret) == 0 {
		t.Fatal("expected secrets")
	}
	if len(r.IP) != 0 {
		t.Fatalf("expected no IP when categories=secret,jwt got %d", len(r.IP))
	}
}

func TestScanContentOpts(t *testing.T) {
	r := ScanContentOpts(`token="xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx"`, "stdin", ScanOptions{Categories: []string{"secret"}})
	if len(r.Secret) == 0 {
		t.Fatal("expected secret from stdin content")
	}
}
