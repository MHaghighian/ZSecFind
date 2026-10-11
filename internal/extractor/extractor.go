package extractor

import (
	"sort"
	"strconv"
	"strings"

	"github.com/l4tr0d3ctism/ZSecFind/internal/model"
)

// Options controls what Extract runs. Empty Categories means all categories.
type Options struct {
	Categories []string
}

// Extract runs all regex rules against content.
func Extract(content, source string) *model.ScanResult {
	return ExtractOpts(content, source, Options{})
}

// ExtractOpts runs selected category matchers against content.
func ExtractOpts(content, source string, opts Options) *model.ScanResult {
	initPatterns()

	want := categorySet(opts.Categories)
	raw := extractRaw(content, source, want)
	result := &model.ScanResult{
		Stats: make(map[string]int),
	}

	addFindings := func(key string, findings []model.Finding) {
		if len(findings) == 0 {
			return
		}
		uniq := uniqueFindings(stripQuoteFindings(findings))
		switch key {
		case "ip":
			result.IP = mergeFindings(result.IP, uniq)
		case "ip_port":
			result.IPPort = mergeFindings(result.IPPort, uniq)
		case "domain":
			result.Domain = mergeFindings(result.Domain, uniq)
		case "path":
			paths, statics := splitStaticFindings(uniq)
			result.Path = mergeFindings(result.Path, paths)
			result.Static = mergeFindings(result.Static, statics)
		case "incomplete_path":
			result.IncompletePath = mergeFindings(result.IncompletePath, uniq)
		case "url":
			urls, statics := splitStaticFindings(uniq)
			result.URL = mergeFindings(result.URL, urls)
			result.Static = mergeFindings(result.Static, statics)
		case "sfz":
			result.SFZ = mergeFindings(result.SFZ, uniq)
		case "mobile":
			result.Mobile = mergeFindings(result.Mobile, uniq)
		case "mail":
			result.Mail = mergeFindings(result.Mail, filterMailFindings(uniq))
		case "jwt":
			result.JWT = mergeFindings(result.JWT, uniq)
		case "algorithm":
			result.Algorithm = mergeFindings(result.Algorithm, uniq)
		case "secret":
			result.Secret = mergeFindings(result.Secret, uniq)
		}
	}

	addFindings("sfz", raw["sfz"])
	addFindings("mobile", raw["mobile"])
	addFindings("mail", raw["mail"])
	addFindings("ip", raw["ip"])
	addFindings("ip_port", raw["ip_port"])
	addFindings("domain", raw["domain"])
	addFindings("path", raw["path"])
	addFindings("incomplete_path", raw["incomplete_path"])
	addFindings("url", raw["url"])
	addFindings("jwt", raw["jwt"])
	addFindings("algorithm", raw["algorithm"])
	addFindings("secret", raw["secret"])

	result.Stats = countStats(result)
	return result
}

func categorySet(categories []string) map[string]bool {
	if len(categories) == 0 {
		return nil
	}
	want := make(map[string]bool, len(categories))
	for _, c := range categories {
		c = strings.ToLower(strings.TrimSpace(c))
		if c != "" {
			want[c] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	return want
}

func wantCategory(want map[string]bool, name string) bool {
	if want == nil {
		return true
	}
	return want[name]
}

// Merge combines two scan results (e.g. page + linked JS files).
func Merge(base, other *model.ScanResult) *model.ScanResult {
	if base == nil {
		return other
	}
	if other == nil {
		return base
	}
	base.IP = mergeFindings(base.IP, other.IP)
	base.IPPort = mergeFindings(base.IPPort, other.IPPort)
	base.Domain = mergeFindings(base.Domain, other.Domain)
	base.Path = mergeFindings(base.Path, other.Path)
	base.IncompletePath = mergeFindings(base.IncompletePath, other.IncompletePath)
	base.URL = mergeFindings(base.URL, other.URL)
	base.Static = mergeFindings(base.Static, other.Static)
	base.SFZ = mergeFindings(base.SFZ, other.SFZ)
	base.Mobile = mergeFindings(base.Mobile, other.Mobile)
	base.Mail = mergeFindings(base.Mail, other.Mail)
	base.JWT = mergeFindings(base.JWT, other.JWT)
	base.Algorithm = mergeFindings(base.Algorithm, other.Algorithm)
	base.Secret = mergeFindings(base.Secret, other.Secret)
	base.Sources = uniqueSorted(append(base.Sources, other.Sources...))
	base.Stats = countStats(base)
	return base
}

func filterMailFindings(items []model.Finding) []model.Finding {
	badTLD := map[string]bool{"js": true, "css": true, "jpg": true, "jpeg": true, "png": true, "ico": true}
	var out []model.Finding
	for _, item := range items {
		s := strings.Trim(item.Value, `"'`)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			continue
		}
		dot := strings.LastIndex(s, ".")
		if dot <= at {
			continue
		}
		tld := strings.ToLower(s[dot+1:])
		if badTLD[tld] {
			continue
		}
		out = append(out, item)
	}
	return out
}

func extractRaw(data, source string, want map[string]bool) map[string][]model.Finding {
	out := make(map[string][]model.Finding)
	lineStarts := buildLineStarts(data)

	if wantCategory(want, "sfz") {
		out["sfz"] = findingsFromRegex(reSFZ, data, source, "sfz", lineStarts)
	}
	if wantCategory(want, "mobile") {
		out["mobile"] = findingsFromRegex(reMobile, data, source, "mobile", lineStarts)
	}
	if wantCategory(want, "mail") {
		out["mail"] = findingsFromRegex(reMail, data, source, "mail", lineStarts)
	}
	if wantCategory(want, "ip") {
		out["ip"] = findingsFromRegex(reIP, data, source, "ip", lineStarts)
	}
	if wantCategory(want, "ip_port") {
		out["ip_port"] = findingsFromRegex(reIPPort, data, source, "ip_port", lineStarts)
	}
	if wantCategory(want, "domain") {
		out["domain"] = findingsFromRegex(reDomain, data, source, "domain", lineStarts)
	}
	if wantCategory(want, "path") {
		out["path"] = findingsFromRegex(rePath, data, source, "path", lineStarts)
	}
	if wantCategory(want, "incomplete_path") {
		out["incomplete_path"] = findingsFromRegex(reIncompletePath, data, source, "incomplete_path", lineStarts)
	}
	if wantCategory(want, "url") {
		out["url"] = findingsFromRegex(reURL, data, source, "url", lineStarts)
	}
	if wantCategory(want, "jwt") {
		out["jwt"] = findingsFromRegex(reJWT, data, source, "jwt", lineStarts)
	}
	if wantCategory(want, "algorithm") {
		out["algorithm"] = findingsFromRegex(reAlgorithm, data, source, "algorithm", lineStarts)
	}
	if wantCategory(want, "secret") {
		out["secret"] = extractSecrets(data, source, lineStarts)
	}

	// URL-derived IP/domain enrichment only when those categories are wanted.
	if urls := out["url"]; len(urls) > 0 {
		for _, u := range urls {
			if wantCategory(want, "ip") {
				out["ip"] = mergeFindings(out["ip"], findingsFromRegex(reIPInURL, u.Value, source, "ip_in_url", nil))
			}
			if wantCategory(want, "ip_port") {
				out["ip_port"] = mergeFindings(out["ip_port"], findingsFromRegex(reIPPortInURL, u.Value, source, "ip_port_in_url", nil))
			}
			if wantCategory(want, "domain") {
				out["domain"] = mergeFindings(out["domain"], findingsFromRegex(reDomainInURL, u.Value, source, "domain_in_url", nil))
			}
		}
	}
	return out
}

func extractSecrets(data, source string, lineStarts []int) []model.Finding {
	seen := make(map[string]struct{})
	var result []model.Finding
	if lineStarts == nil {
		lineStarts = buildLineStarts(data)
	}

	indices := secretIndex.eligibleSecretIndices(data)
	// Match prior reverse-iteration preference: higher index (later-loaded curated) first.
	sort.Slice(indices, func(i, j int) bool { return indices[i] > indices[j] })

	for _, i := range indices {
		sp := secretPatterns[i]
		for _, idx := range sp.re.FindAllStringIndex(data, -1) {
			value := data[idx[0]:idx[1]]
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			loc := findingAt(data, lineStarts, source, sp.ruleID, idx[0], idx[1])
			result = append(result, loc.toFinding())
		}
	}
	return result
}

func stripQuoteFindings(items []model.Finding) []model.Finding {
	out := make([]model.Finding, len(items))
	for i, item := range items {
		out[i] = item
		out[i].Value = stripQuotesSingle(item.Value)
	}
	return out
}

func stripQuotesSingle(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') {
		s = s[1:]
	}
	if len(s) >= 1 && (s[len(s)-1] == '\'' || s[len(s)-1] == '"') {
		s = s[:len(s)-1]
	}
	return s
}

func splitStaticFindings(items []model.Finding) (nonStatic, static []model.Finding) {
	for _, item := range items {
		if isStaticAsset(item.Value) {
			static = append(static, item)
		} else {
			nonStatic = append(nonStatic, item)
		}
	}
	return
}

func isStaticAsset(item string) bool {
	for _, ext := range staticExtensions {
		if strings.Contains(item, ext) {
			if ext == ".js" && strings.Contains(item, ".jsp") {
				continue
			}
			return true
		}
	}
	return false
}

func mergeFindings(a, b []model.Finding) []model.Finding {
	seen := make(map[string]struct{})
	var out []model.Finding
	for _, f := range append(a, b...) {
		key := findingKey(f)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source == out[j].Source {
			if out[i].StartLine == out[j].StartLine {
				return out[i].Value < out[j].Value
			}
			return out[i].StartLine < out[j].StartLine
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func findingKey(f model.Finding) string {
	return f.Value + "\x00" + f.Source + "\x00" + strconv.Itoa(f.StartLine) + "\x00" + f.RuleID
}

func uniqueFindings(items []model.Finding) []model.Finding {
	return mergeFindings(nil, items)
}

func uniqueSorted(items []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func countStats(r *model.ScanResult) map[string]int {
	return map[string]int{
		"ip":              len(r.IP),
		"ip_port":         len(r.IPPort),
		"domain":          len(r.Domain),
		"path":            len(r.Path),
		"incomplete_path": len(r.IncompletePath),
		"url":             len(r.URL),
		"static":          len(r.Static),
		"sfz":             len(r.SFZ),
		"mobile":          len(r.Mobile),
		"mail":            len(r.Mail),
		"jwt":             len(r.JWT),
		"algorithm":       len(r.Algorithm),
		"secret":          len(r.Secret),
	}
}

// PatternCount returns loaded secret pattern count (for --version diagnostics).
func PatternCount() int {
	initPatterns()
	return len(secretPatterns)
}
