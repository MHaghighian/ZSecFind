package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestScanURLSafeModeFetchesJSNotCSS(t *testing.T) {
	var jsHits, cssHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Relative /style.css must NOT be fetched (absolute URL not in HTML).
		// Absolute external URL that appears in href SHOULD be fetched (legacy safe mode).
		_, _ = w.Write([]byte(`<!doctype html><html><head>
<link href="/style.css" rel="stylesheet">
<script src="/app.js"></script>
</head><body>ok</body></html>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		jsHits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`const token = "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx";`))
	})
	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		cssHits.Add(1)
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte(`body { color: red }`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r, err := ScanURL(context.Background(), srv.URL+"/", Options{
		SafeMode:    true,
		Timeout:     5 * time.Second,
		Concurrency: 4,
		Categories:  []string{"secret", "jwt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if jsHits.Load() != 1 {
		t.Fatalf("expected 1 JS fetch, got %d", jsHits.Load())
	}
	if cssHits.Load() != 0 {
		t.Fatalf("relative CSS absolute URL is not in HTML; should not fetch, got %d", cssHits.Load())
	}
	if len(r.Secret) == 0 {
		t.Fatal("expected secret from app.js to be merged")
	}
	joined := strings.Join(r.Sources, ",")
	if !strings.Contains(joined, "/app.js") {
		t.Fatalf("sources missing app.js: %v", r.Sources)
	}
}

func TestScanURLSafeModeFetchesAbsoluteHrefWhenScriptPresent(t *testing.T) {
	// Legacy safe-mode coverage: absolute href string in HTML + any <script> => fetch.
	var extHits atomic.Int32
	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`
<script src="/noop.js"></script>
<a href="%s/external.html">ext</a>
`, srvURL)))
	})
	mux.HandleFunc("/noop.js", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`// noop`))
	})
	mux.HandleFunc("/external.html", func(w http.ResponseWriter, r *http.Request) {
		extHits.Add(1)
		_, _ = w.Write([]byte(`token = "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx"`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL

	r, err := ScanURL(context.Background(), srv.URL+"/", Options{
		SafeMode:    true,
		Timeout:     5 * time.Second,
		Categories:  []string{"secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if extHits.Load() != 1 {
		t.Fatalf("expected absolute href fetch under legacy safe mode, got %d", extHits.Load())
	}
	if len(r.Secret) == 0 {
		t.Fatal("expected secret from external.html")
	}
}

func TestScanURLBodyNoCrawl(t *testing.T) {
	var linkedHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<script src="/secret.js"></script>`))
	})
	mux.HandleFunc("/secret.js", func(w http.ResponseWriter, r *http.Request) {
		linkedHits.Add(1)
		_, _ = w.Write([]byte(`xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r, err := ScanURLBody(context.Background(), srv.URL+"/", Options{
		Timeout:    5 * time.Second,
		Categories: []string{"secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if linkedHits.Load() != 0 {
		t.Fatalf("ScanURLBody must not fetch links, got %d", linkedHits.Load())
	}
	if len(r.Secret) != 0 {
		t.Fatalf("page body has no secrets, got %d", len(r.Secret))
	}
}

func TestScanURLConcurrentScripts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`
<script src="/a.js"></script>
<script src="/b.js"></script>
<script src="/c.js"></script>
`))
	})
	for _, name := range []string{"/a.js", "/b.js", "/c.js"} {
		path := name
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`var x = "hf_` + strings.Repeat("a", 34) + `";`))
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r, err := ScanURL(context.Background(), srv.URL+"/", Options{
		SafeMode:    true,
		Timeout:     5 * time.Second,
		Concurrency: 3,
		Categories:  []string{"secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Sources) < 4 {
		t.Fatalf("expected page + 3 js sources, got %v", r.Sources)
	}
	if len(r.Secret) == 0 {
		t.Fatal("expected secrets from JS files")
	}
}

func TestScanURLCategoriesSkipIP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`
ip 203.0.113.77
token xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx
<script src="/x.js"></script>
`))
	})
	mux.HandleFunc("/x.js", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`// noop`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r, err := ScanURL(context.Background(), srv.URL+"/", Options{
		SafeMode:    true,
		Timeout:     5 * time.Second,
		Categories:  []string{"secret", "jwt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.IP) != 0 {
		t.Fatalf("expected no IP when categories=secret,jwt got %d", len(r.IP))
	}
	if len(r.Secret) == 0 {
		t.Fatal("expected secret findings")
	}
}

func TestCollectLinksMarksScript(t *testing.T) {
	base, _ := http.NewRequest(http.MethodGet, "https://example.com/app/", nil)
	links := collectLinks(`
<link href="/style.css">
<script src="/bundle.js"></script>
<img src="/logo.png">
`, base.URL)
	byURL := map[string]bool{}
	for _, l := range links {
		byURL[l.URL] = l.FromScript
	}
	if !byURL["https://example.com/bundle.js"] {
		t.Fatalf("bundle.js should be FromScript: %#v", links)
	}
	if byURL["https://example.com/style.css"] {
		t.Fatal("style.css should not be FromScript")
	}
}
