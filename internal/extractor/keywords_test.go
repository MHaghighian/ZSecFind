package extractor

import (
	"strings"
	"testing"
)

func TestExtractKeywordsFromPattern(t *testing.T) {
	cases := []struct {
		pat     string
		wantAny []string // at least one of these should appear
		always  bool     // expect no keywords
	}{
		{pat: `\b(sk-ant-api03-[\w\-]{93}AA)\b`, wantAny: []string{"sk-ant-api03-"}},
		{pat: `xox[bpar]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-_]{10,}`, wantAny: []string{"xox"}},
		{pat: `\b(hf_[a-zA-Z0-9]{34})\b`, wantAny: []string{"hf_"}},
		{pat: `(?i)authorization:\s*bearer`, wantAny: []string{"authorization"}},
		{pat: `[a-f0-9]{32}`, always: true},
		{pat: `\b([a-zA-Z0-9]{20,})\b`, always: true},
		{pat: `https://discord(?:app)?\.com/api/webhooks/[0-9]{18,20}/[0-9a-zA-Z\-_]{68}`, wantAny: []string{"discord"}},
		{pat: `\b(secret_[a-zA-Z0-9]{43})\b`, wantAny: []string{"secret_"}},
		{pat: `https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9_-]{16,}`, wantAny: []string{"hooks"}},
	}
	for _, tc := range cases {
		kws, _ := extractKeywordsFromPattern(tc.pat)
		if tc.always {
			if len(kws) != 0 {
				t.Errorf("pattern %q: want always-on (no keywords), got %v", tc.pat, kws)
			}
			continue
		}
		found := false
		joined := strings.Join(kws, " ")
		for _, w := range tc.wantAny {
			if strings.Contains(joined, strings.ToLower(w)) || containsFold(kws, w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("pattern %q: keywords %v missing any of %v", tc.pat, kws, tc.wantAny)
		}
	}
}

func containsFold(ss []string, want string) bool {
	want = strings.ToLower(want)
	for _, s := range ss {
		if strings.ToLower(s) == want || strings.Contains(strings.ToLower(s), want) {
			return true
		}
	}
	return false
}

func TestExtractOptsOnlySecretsSkipsIP(t *testing.T) {
	content := `
		const ip = "203.0.113.77";
		const key = "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx";
	`
	full := Extract(content, "test")
	if len(full.IP) == 0 {
		t.Fatal("expected IP in full extract")
	}
	if len(full.Secret) == 0 {
		t.Fatal("expected secret in full extract")
	}

	filtered := ExtractOpts(content, "test", Options{Categories: []string{"secret", "jwt"}})
	if len(filtered.IP) != 0 {
		t.Fatalf("expected no IP when only secrets, got %d", len(filtered.IP))
	}
	if len(filtered.Secret) == 0 {
		t.Fatal("expected secrets when only-secrets categories set")
	}
}

func TestPrefilterMatchesFullExtract(t *testing.T) {
	samples := []string{
		`key = "sk-proj-abc123T3BlbkFJxyz789secretkeyhere"`,
		`sk-ant-api03-` + strings.Repeat("a", 93) + `AA`,
		`xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx`,
		`https://discord.com/api/webhooks/1234567890123456789/` + strings.Repeat("a", 68),
		`hf_` + strings.Repeat("a", 34),
		`secret_` + strings.Repeat("a", 43),
		`AKIAIOSFODNN7EXAMPLE`,
		`ghp_` + strings.Repeat("x", 36),
		`plain text with no secrets at all hello world`,
	}
	for _, content := range samples {
		r := Extract(content, "test")
		// Ensure extract completes; curated samples should still hit where expected.
		_ = r
	}
	// Curated samples that must match
	must := map[string]string{
		"openai":    `key = "sk-proj-abc123T3BlbkFJxyz789secretkeyhere"`,
		"slack":     `xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx`,
		"huggingface": `hf_` + strings.Repeat("a", 34),
	}
	for name, content := range must {
		r := Extract(content, "test")
		if len(r.Secret) == 0 {
			t.Errorf("prefilter broke detection for %s", name)
		}
	}
}
