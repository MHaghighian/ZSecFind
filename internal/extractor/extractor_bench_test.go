package extractor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func BenchmarkExtractSampleHTML(b *testing.B) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample.html"))
	if err != nil {
		b.Fatal(err)
	}
	content := string(data)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Extract(content, "bench")
	}
}

func BenchmarkExtractSecretsOnly(b *testing.B) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample.html"))
	if err != nil {
		b.Fatal(err)
	}
	content := string(data)
	opts := Options{Categories: []string{"secret", "jwt"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractOpts(content, "bench", opts)
	}
}

func BenchmarkExtractCleanLarge(b *testing.B) {
	// Large file with no vendor secret prefixes — prefilter should skip most regexes.
	var sb strings.Builder
	sb.Grow(200_000)
	for i := 0; i < 4000; i++ {
		sb.WriteString("function render(view) { return view.map(x => x.id + '-' + x.name).join(','); }\n")
	}
	content := sb.String()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractOpts(content, "bench", Options{Categories: []string{"secret"}})
	}
}

func BenchmarkExtractVulnerableConfig(b *testing.B) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vulnerable-app", "assets", "js", "config.js"))
	if err != nil {
		b.Fatal(err)
	}
	content := string(data)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Extract(content, "bench")
	}
}
