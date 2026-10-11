package crawler

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/l4tr0d3ctism/ZSecFind/internal/extractor"
	"github.com/l4tr0d3ctism/ZSecFind/internal/model"
)

// Options controls HTTP crawling behavior.
type Options struct {
	SafeMode    bool
	Timeout     time.Duration
	Concurrency int
	MaxDepth    int
	UserAgent   string
	// Categories limits extractors (empty = all). Same names as --only.
	Categories []string
}

type linkRef struct {
	URL        string
	FromScript bool
}

var (
	reHref      = regexp.MustCompile(`href=['"](.*?)['"]`)
	reSrc       = regexp.MustCompile(`src=['"](.*?)['"]`)
	reScriptSrc = regexp.MustCompile(`(?i)<script[^>]+src=['"](.*?)['"]`)
)

func defaultUserAgent() string {
	return "ZSecFind-CLI/1.0 (DevSecOps)"
}

func newHTTPClient(timeout time.Duration, concurrency int) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if concurrency <= 0 {
		concurrency = 8
	}
	perHost := concurrency
	if perHost < 8 {
		perHost = 8
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   perHost,
		MaxConnsPerHost:       perHost * 2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func normalizeOpts(opts *Options) {
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	if opts.UserAgent == "" {
		opts.UserAgent = defaultUserAgent()
	}
}

func extractOpts(opts Options) extractor.Options {
	return extractor.Options{Categories: opts.Categories}
}

// ScanURL fetches a URL, extracts findings, and optionally crawls linked assets.
func ScanURL(ctx context.Context, rawURL string, opts Options) (*model.ScanResult, error) {
	normalizeOpts(&opts)

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}

	client := newHTTPClient(opts.Timeout, opts.Concurrency)
	body, err := fetch(ctx, client, rawURL, opts.UserAgent)
	if err != nil {
		return nil, err
	}
	page := string(body)

	result := extractor.ExtractOpts(page, rawURL, extractOpts(opts))
	result.Target = rawURL
	result.Sources = []string{rawURL}

	links := collectLinks(page, parsed)
	// Match historical safe-mode coverage: .js paths, <script src>, or any
	// absolute URL that appears in the HTML when the page contains a <script>
	// (legacy isScriptTag behavior). Do not shrink the fetch set for speed.
	hasScript := strings.Contains(page, "<script") || strings.Contains(page, "<Script")
	toFetch := make([]string, 0, len(links))
	seenFetch := make(map[string]struct{})
	for _, link := range links {
		if link.URL == rawURL {
			continue
		}
		if opts.SafeMode && !shouldFetchInSafeMode(link, page, hasScript) {
			continue
		}
		if _, ok := seenFetch[link.URL]; ok {
			continue
		}
		seenFetch[link.URL] = struct{}{}
		toFetch = append(toFetch, link.URL)
	}
	if len(toFetch) == 0 {
		return result, nil
	}

	var mu sync.Mutex
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	xopts := extractOpts(opts)

	for _, link := range toFetch {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			data, err := fetch(ctx, client, u, opts.UserAgent)
			if err != nil {
				return
			}
			sub := extractor.ExtractOpts(string(data), u, xopts)
			mu.Lock()
			result = extractor.Merge(result, sub)
			result.Sources = append(result.Sources, u)
			mu.Unlock()
		}(link)
	}
	wg.Wait()
	result.Sources = unique(result.Sources)
	result.Stats = countFromResult(result)
	return result, nil
}

// ScanURLBody fetches a single URL without following links.
func ScanURLBody(ctx context.Context, rawURL string, opts Options) (*model.ScanResult, error) {
	normalizeOpts(&opts)
	client := newHTTPClient(opts.Timeout, opts.Concurrency)
	body, err := fetch(ctx, client, rawURL, opts.UserAgent)
	if err != nil {
		return nil, err
	}
	r := extractor.ExtractOpts(string(body), rawURL, extractOpts(opts))
	r.Target = rawURL
	r.Sources = []string{rawURL}
	return r, nil
}

// ScanContent scans raw HTML/JS without HTTP.
func ScanContent(content, source string) *model.ScanResult {
	r := extractor.Extract(content, source)
	r.Target = source
	r.Sources = []string{source}
	return r
}

func fetch(ctx context.Context, client *http.Client, u, ua string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("fetch %s: status %d", u, resp.StatusCode)
	}

	const maxBody = 10 << 20 // 10MB
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", u, err)
	}
	return data, nil
}

func collectLinks(source string, base *url.URL) []linkRef {
	seen := make(map[string]*linkRef)
	var order []string

	add := func(raw string, fromScript bool) {
		resolved := resolveURL(base, raw)
		if resolved == "" {
			return
		}
		if existing, ok := seen[resolved]; ok {
			if fromScript {
				existing.FromScript = true
			}
			return
		}
		ref := &linkRef{URL: resolved, FromScript: fromScript}
		seen[resolved] = ref
		order = append(order, resolved)
	}

	for _, m := range reHref.FindAllStringSubmatch(source, -1) {
		add(m[1], false)
	}
	for _, m := range reSrc.FindAllStringSubmatch(source, -1) {
		add(m[1], false)
	}
	for _, m := range reScriptSrc.FindAllStringSubmatch(source, -1) {
		add(m[1], true)
	}

	out := make([]linkRef, 0, len(order))
	for _, u := range order {
		out = append(out, *seen[u])
	}
	return out
}

func resolveURL(base *url.URL, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "mailto:") {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

func isJavaScript(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(parsed.Path), ".js")
}

// shouldFetchInSafeMode preserves pre-optimization crawl coverage.
// Historical rule: fetch .js, script src, or links whose absolute URL appears
// in the page HTML when any <script> is present.
func shouldFetchInSafeMode(link linkRef, page string, hasScript bool) bool {
	if link.FromScript || isJavaScript(link.URL) {
		return true
	}
	return hasScript && strings.Contains(page, link.URL)
}

func unique(items []string) []string {
	m := make(map[string]struct{})
	var out []string
	for _, i := range items {
		if _, ok := m[i]; ok {
			continue
		}
		m[i] = struct{}{}
		out = append(out, i)
	}
	return out
}

func countFromResult(r *model.ScanResult) map[string]int {
	return map[string]int{
		"ip": len(r.IP), "ip_port": len(r.IPPort), "domain": len(r.Domain),
		"path": len(r.Path), "incomplete_path": len(r.IncompletePath),
		"url": len(r.URL), "static": len(r.Static), "sfz": len(r.SFZ),
		"mobile": len(r.Mobile), "mail": len(r.Mail), "jwt": len(r.JWT),
		"algorithm": len(r.Algorithm), "secret": len(r.Secret),
	}
}
