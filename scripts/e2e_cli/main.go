package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func main() {
	root, _ := os.Getwd()
	bin := filepath.Join(root, "zsecfind.exe")
	if runtime.GOOS != "windows" {
		bin = filepath.Join(root, "zsecfind")
	}
	if _, err := os.Stat(bin); err != nil {
		fmt.Fprintf(os.Stderr, "binary not found: %s (run go build first)\n", bin)
		os.Exit(1)
	}

	passed, failed := 0, 0
	check := func(name string, ok bool, detail string) {
		if ok {
			fmt.Printf("  [PASS] %s\n", name)
			passed++
			return
		}
		fmt.Printf("  [FAIL] %s — %s\n", name, detail)
		failed++
	}

	run := func(args ...string) (int, string, string) {
		cmd := exec.Command(bin, args...)
		var stdout, stderr strings.Builder
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				code = -1
			}
		}
		return code, stdout.String(), stderr.String()
	}

	fmt.Println("=== ZSecFind CLI E2E Tests ===")
	fmt.Println()

	// --version
	code, out, _ := run("--version")
	check("--version exits 0", code == 0 && strings.Contains(out, "zsecfind"), fmt.Sprintf("code=%d out=%q", code, out))

	// single file JSON
	sample := filepath.Join("testdata", "sample.html")
	code, out, _ = run("-q", sample)
	var report map[string]any
	jsonOK := json.Unmarshal([]byte(out), &report) == nil
	summary, _ := report["summary"].(map[string]any)
	hasSensitive, _ := summary["has_sensitive"].(bool)
	check("positional file scan (JSON)", code == 0 && jsonOK && hasSensitive, "expected valid JSON with sensitive findings")

	// rule_id + line in findings
	findings, _ := report["findings"].(map[string]any)
	secretList, _ := findings["secret"].([]any)
	hasMeta := false
	if len(secretList) > 0 {
		if item, ok := secretList[0].(map[string]any); ok {
			_, hasRule := item["rule_id"]
			_, hasLine := item["start_line"]
			hasMeta = hasRule && hasLine
		}
	}
	check("finding has rule_id + start_line", hasMeta, "missing metadata in secret finding")

	// text format
	code, out, _ = run("-q", "--format", "text", sample)
	check("text format", code == 0 && strings.Contains(out, "SECRET"), out[:min(80, len(out))])

	// directory + workers
	vuln := filepath.Join("testdata", "vulnerable-app")
	code, out1, _ := run("-q", "--workers", "1", vuln)
	code2, out2, _ := run("-q", "--workers", "4", vuln)
	var r1, r2 map[string]any
	json.Unmarshal([]byte(out1), &r1)
	json.Unmarshal([]byte(out2), &r2)
	s1, _ := r1["summary"].(map[string]any)
	s2, _ := r2["summary"].(map[string]any)
	t1, _ := s1["total_findings"].(float64)
	t2, _ := s2["total_findings"].(float64)
	check("dir scan --workers 1 vs 4 same count", code == 0 && code2 == 0 && t1 == t2 && t1 > 0,
		fmt.Sprintf("workers1=%v workers4=%v", t1, t2))

	// -d flag
	code, out, _ = run("-q", "-d", vuln)
	jsonOK = json.Unmarshal([]byte(out), &report) == nil
	check("-d directory flag", code == 0 && jsonOK, "invalid json")

	// -f flag
	configJS := filepath.Join(vuln, "assets", "js", "config.js")
	code, out, _ = run("-q", "-f", configJS)
	json.Unmarshal([]byte(out), &report)
	summary, _ = report["summary"].(map[string]any)
	fs, _ := summary["files_scanned"].(float64)
	check("-f file flag", code == 0 && fs == 1, fmt.Sprintf("files_scanned=%v", fs))

	// --only-secrets
	code, out, _ = run("-q", "--only-secrets", sample)
	json.Unmarshal([]byte(out), &report)
	findings, _ = report["findings"].(map[string]any)
	_, hasIP := findings["ip"]
	_, hasSecret := findings["secret"]
	check("--only-secrets filter", code == 0 && hasSecret && !hasIP, fmt.Sprintf("findings keys: %v", keys(findings)))

	// --only category
	code, out, _ = run("-q", "--only", "jwt", sample)
	json.Unmarshal([]byte(out), &report)
	findings, _ = report["findings"].(map[string]any)
	_, hasJWT := findings["jwt"]
	_, hasSecret2 := findings["secret"]
	check("--only jwt", code == 0 && hasJWT && !hasSecret2, "expected only jwt")

	// --fail-on-find (should exit 1)
	code, _, _ = run("-q", "--fail-on-find", configJS)
	check("--fail-on-find exit 1 on secrets", code == 1, fmt.Sprintf("exit=%d", code))

	// clean file should exit 0
	css := filepath.Join(vuln, "assets", "css", "main.css")
	code, _, _ = run("-q", "--fail-on-find", css)
	check("--fail-on-find exit 0 when clean", code == 0, fmt.Sprintf("exit=%d", code))

	// flags after positional
	code, out, _ = run(sample, "-q", "--format", "json")
	check("flags after positional path", code == 0 && json.Unmarshal([]byte(out), &report) == nil, "parse failed")

	// output file
	tmpOut := filepath.Join(os.TempDir(), "zsecfind-e2e-out.json")
	defer os.Remove(tmpOut)
	code, _, _ = run("-q", "-o", tmpOut, sample)
	data, readErr := os.ReadFile(tmpOut)
	check("-o output file", code == 0 && readErr == nil && len(data) > 10, fmt.Sprintf("readErr=%v len=%d", readErr, len(data)))

	// stdin
	cmd := exec.Command(bin, "-q")
	cmd.Stdin = strings.NewReader(`token = "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx"`)
	var stdout strings.Builder
	cmd.Stdout = &stdout
	_ = cmd.Run()
	json.Unmarshal([]byte(stdout.String()), &report)
	summary, _ = report["summary"].(map[string]any)
	tf, _ := summary["total_findings"].(float64)
	check("stdin scan", tf > 0, fmt.Sprintf("findings=%v", tf))

	// Golden: vulnerable-app --only-secrets must hit known vendor prefixes
	start := time.Now()
	code, out, _ = run("-q", "--only-secrets", vuln)
	elapsed := time.Since(start)
	json.Unmarshal([]byte(out), &report)
	findings, _ = report["findings"].(map[string]any)
	secretList, _ = findings["secret"].([]any)
	secretBlob := ""
	for _, item := range secretList {
		if m, ok := item.(map[string]any); ok {
			if v, ok := m["value"].(string); ok {
				secretBlob += v + "\n"
			}
		}
	}
	needles := []string{"AKIA", "ghp_", "hooks.slack.com", "sk_live_", "glpat-", "AIza"}
	goldenOK := code == 0 && len(secretList) >= 5
	missing := []string{}
	for _, n := range needles {
		if !strings.Contains(secretBlob, n) {
			missing = append(missing, n)
			goldenOK = false
		}
	}
	check("golden vulnerable-app --only-secrets", goldenOK,
		fmt.Sprintf("secrets=%d missing=%v", len(secretList), missing))
	fmt.Printf("  [INFO] vulnerable-app --only-secrets wall time: %s (%d secrets)\n", elapsed.Round(time.Millisecond), len(secretList))

	// Clean CSS has no secrets under --only-secrets
	code, out, _ = run("-q", "--only-secrets", css)
	json.Unmarshal([]byte(out), &report)
	summary, _ = report["summary"].(map[string]any)
	hs, _ := summary["has_sensitive"].(bool)
	secCount, _ := summary["by_category"].(map[string]any)
	secN := 0.0
	if secCount != nil {
		secN, _ = secCount["secret"].(float64)
	}
	check("clean css --only-secrets empty", code == 0 && !hs && secN == 0,
		fmt.Sprintf("has_sensitive=%v secret_count=%v", hs, secN))

	fmt.Println()
	fmt.Printf("Result: %d passed, %d failed\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
