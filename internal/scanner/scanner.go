package scanner

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/l4tr0d3ctism/ZSecFind/internal/crawler"
	"github.com/l4tr0d3ctism/ZSecFind/internal/extractor"
	"github.com/l4tr0d3ctism/ZSecFind/internal/model"
)

// ScanOptions configures directory scanning.
type ScanOptions struct {
	Workers    int
	Extensions []string
	// Categories limits extractors (empty = all). Same names as --only.
	Categories []string
}

// ScanFile reads a local file and extracts findings.
func ScanFile(path string) (*model.ScanResult, error) {
	return ScanFileOpts(path, ScanOptions{})
}

// ScanFileOpts reads a local file with optional category filtering at extract time.
func ScanFileOpts(path string, opts ScanOptions) (*model.ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := extractor.ExtractOpts(string(data), path, extractor.Options{Categories: opts.Categories})
	r.Target = path
	r.Sources = []string{path}
	return r, nil
}

// ScanDir walks a directory and scans text-like files.
func ScanDir(root string, opts ScanOptions) ([]*model.ScanResult, error) {
	extensions := opts.Extensions
	if len(extensions) == 0 {
		extensions = []string{".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".vue", ".json", ".xml", ".txt", ".env", ".yaml", ".yml", ".php", ".jsp", ".asp", ".aspx", ".cs", ".java", ".py", ".rb", ".go", ".css", ".md"}
	}
	extSet := make(map[string]bool)
	for _, e := range extensions {
		extSet[strings.ToLower(e)] = true
	}

	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" || base == "vendor" || base == "third_party" || base == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !extSet[ext] {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, nil
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > len(paths) {
		workers = len(paths)
	}

	jobs := make(chan string)
	results := make(chan *model.ScanResult, workers)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				r, scanErr := ScanFileOpts(path, opts)
				if scanErr != nil {
					continue
				}
				if r.TotalFindings() > 0 {
					results <- r
				}
			}
		}()
	}

	go func() {
		for _, path := range paths {
			jobs <- path
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var out []*model.ScanResult
	for r := range results {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Target < out[j].Target
	})
	return out, nil
}

// ScanURL wraps crawler with context.
func ScanURL(ctx context.Context, u string, opts crawler.Options) (*model.ScanResult, error) {
	return crawler.ScanURL(ctx, u, opts)
}

// ScanContent scans in-memory content.
func ScanContent(content, source string) *model.ScanResult {
	return ScanContentOpts(content, source, ScanOptions{})
}

// ScanContentOpts scans in-memory content with optional category filtering.
func ScanContentOpts(content, source string, opts ScanOptions) *model.ScanResult {
	r := extractor.ExtractOpts(content, source, extractor.Options{Categories: opts.Categories})
	r.Target = source
	r.Sources = []string{source}
	return r
}
