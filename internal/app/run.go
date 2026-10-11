package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/l4tr0d3ctism/ZSecFind/internal/crawler"
	"github.com/l4tr0d3ctism/ZSecFind/internal/extractor"
	"github.com/l4tr0d3ctism/ZSecFind/internal/model"
	"github.com/l4tr0d3ctism/ZSecFind/internal/output"
	"github.com/l4tr0d3ctism/ZSecFind/internal/scanner"
)

// Version is set by the linker or defaults for dev builds.
var Version = "1.0.0"

// Run executes the CLI and returns an exit code.
func Run() int {
	var (
		urls        string
		files       string
		dir         string
		outPath     string
		format      string
		safeMode    bool
		noCrawl     bool
		timeoutSec  int
		concurrency int
		workers     int
		failOnFind  bool
		onlySecrets bool
		categories  string
		showVersion bool
		quiet       bool
	)

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&urls, "u", "", "Comma-separated URLs to scan")
	fs.StringVar(&urls, "url", "", "Alias for -u")
	fs.StringVar(&files, "f", "", "Comma-separated local files to scan")
	fs.StringVar(&files, "file", "", "Alias for -f")
	fs.StringVar(&dir, "d", "", "Directory to scan recursively")
	fs.StringVar(&dir, "dir", "", "Alias for -d")
	fs.StringVar(&outPath, "o", "-", "Output file path (- for stdout)")
	fs.StringVar(&format, "format", "json", "Output format: json|text")
	fs.BoolVar(&safeMode, "safe", true, "Safe mode: only fetch .js linked resources (for URL scans)")
	fs.BoolVar(&noCrawl, "no-crawl", false, "Do not fetch linked resources (URL scan only)")
	fs.IntVar(&timeoutSec, "timeout", 15, "HTTP timeout in seconds")
	fs.IntVar(&concurrency, "c", 8, "Concurrent HTTP fetches")
	fs.IntVar(&workers, "workers", 0, "Parallel file scan workers (0 = NumCPU)")
	fs.BoolVar(&failOnFind, "fail-on-find", false, "Exit code 1 when secrets/JWT are found (CI gate)")
	fs.BoolVar(&onlySecrets, "only-secrets", false, "Only report secret and jwt categories")
	fs.StringVar(&categories, "only", "", "Comma-separated categories to include (secret,jwt,ip,...)")
	fs.BoolVar(&showVersion, "version", false, "Print version and exit")
	fs.BoolVar(&quiet, "q", false, "Suppress stderr progress")

	positional, err := parseCLI(fs, os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	if showVersion {
		fmt.Printf("zsecfind %s (patterns: %d)\n", Version, extractor.PatternCount())
		return 0
	}

	output.SetReportVersion(Version)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	crawlOpts := crawler.Options{
		SafeMode:    safeMode,
		Timeout:     time.Duration(timeoutSec) * time.Second,
		Concurrency: concurrency,
	}

	var results []*model.ScanResult
	hasWork := false
	cats := categoryAllowlist(onlySecrets, categories)
	scanOpts := scanner.ScanOptions{Workers: workers, Categories: cats}
	crawlOpts.Categories = cats


	if urls == "" && files == "" && dir == "" && len(positional) == 0 {
		if stat, _ := os.Stdin.Stat(); (stat.Mode() & os.ModeCharDevice) == 0 {
			data, readErr := io.ReadAll(os.Stdin)
			if readErr != nil {
				fatal(quiet, readErr)
				return 1
			}
			results = append(results, applyFilters(scanner.ScanContentOpts(string(data), "stdin", scanOpts), onlySecrets, categories))
			hasWork = true
		}
	}

	for _, u := range splitList(urls) {
		hasWork = true
		r, err := scanURLTarget(ctx, u, crawlOpts, noCrawl, quiet)
		if err != nil {
			fatal(quiet, err)
			return 1
		}
		results = append(results, applyFilters(r, onlySecrets, categories))
	}

	for _, f := range splitList(files) {
		hasWork = true
		r, err := scanFileTarget(f, scanOpts, quiet)
		if err != nil {
			fatal(quiet, err)
			return 1
		}
		results = append(results, applyFilters(r, onlySecrets, categories))
	}

	if dir != "" {
		hasWork = true
		rs, err := scanDirTarget(dir, scanOpts, quiet)
		if err != nil {
			fatal(quiet, err)
			return 1
		}
		for _, r := range rs {
			results = append(results, applyFilters(r, onlySecrets, categories))
		}
	}

	for _, arg := range positional {
		hasWork = true
		rs, err := scanTarget(ctx, arg, crawlOpts, noCrawl, scanOpts, quiet)
		if err != nil {
			fatal(quiet, err)
			return 1
		}
		for _, r := range rs {
			results = append(results, applyFilters(r, onlySecrets, categories))
		}
	}

	if !hasWork {
		rs, err := scanDirTarget(".", scanOpts, quiet)
		if err != nil {
			fatal(quiet, err)
			return 1
		}
		for _, r := range rs {
			results = append(results, applyFilters(r, onlySecrets, categories))
		}
	}

	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "no findings (scan completed)")
	}

	outFmt := output.Format(strings.ToLower(format))
	if err := output.WriteToFile(outPath, results, outFmt); err != nil {
		fatal(quiet, err)
		return 1
	}

	if failOnFind {
		report := model.NewReport(Version, results)
		if report.HasSensitive() {
			if !quiet {
				fmt.Fprintf(os.Stderr, "sensitive findings detected: %d secret(s), %d jwt(s)\n",
					report.Summary.ByCategory["secret"], report.Summary.ByCategory["jwt"])
			}
			return 1
		}
	}

	return 0
}

func scanTarget(ctx context.Context, target string, opts crawler.Options, noCrawl bool, scanOpts scanner.ScanOptions, quiet bool) ([]*model.ScanResult, error) {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		r, err := scanURLTarget(ctx, target, opts, noCrawl, quiet)
		if err != nil {
			return nil, err
		}
		return []*model.ScanResult{r}, nil
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", target, err)
	}
	if info.IsDir() {
		return scanDirTarget(target, scanOpts, quiet)
	}
	r, err := scanFileTarget(target, scanOpts, quiet)
	if err != nil {
		return nil, err
	}
	return []*model.ScanResult{r}, nil
}

func scanURLTarget(ctx context.Context, u string, opts crawler.Options, noCrawl, quiet bool) (*model.ScanResult, error) {
	if !quiet {
		fmt.Fprintf(os.Stderr, "scanning url: %s\n", u)
	}
	return scanURL(ctx, u, opts, noCrawl)
}

func scanFileTarget(path string, scanOpts scanner.ScanOptions, quiet bool) (*model.ScanResult, error) {
	if !quiet {
		fmt.Fprintf(os.Stderr, "scanning file: %s\n", path)
	}
	return scanner.ScanFileOpts(path, scanOpts)
}

func scanDirTarget(path string, scanOpts scanner.ScanOptions, quiet bool) ([]*model.ScanResult, error) {
	if !quiet {
		fmt.Fprintf(os.Stderr, "scanning directory: %s\n", path)
	}
	return scanner.ScanDir(path, scanOpts)
}

func scanURL(ctx context.Context, u string, opts crawler.Options, noCrawl bool) (*model.ScanResult, error) {
	if noCrawl {
		return crawler.ScanURLBody(ctx, u, opts)
	}
	return scanner.ScanURL(ctx, u, opts)
}

func categoryAllowlist(onlySecrets bool, categories string) []string {
	if onlySecrets {
		return []string{"secret", "jwt"}
	}
	return splitList(categories)
}

func applyFilters(r *model.ScanResult, onlySecrets bool, categories string) *model.ScanResult {
	if onlySecrets {
		return output.FilterCategories(r, []string{"secret", "jwt"})
	}
	if categories != "" {
		return output.FilterCategories(r, splitList(categories))
	}
	return r
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fatal(quiet bool, err error) {
	if !quiet {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
}
