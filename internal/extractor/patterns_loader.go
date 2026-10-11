package extractor

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	"github.com/l4tr0d3ctism/ZSecFind/internal/model"
)

// secretPattern is a compiled secret rule with metadata.
type secretPattern struct {
	re              *regexp.Regexp
	ruleID          string
	description     string
	keywords        []string
	caseInsensitive bool
}

// skipBroadPatterns are overly generic regexes that cause noise in passive scans.
var skipBroadPatterns = map[string]bool{
	`\b([a-zA-Z0-9]{30})\b`:    true,
	`[a-f0-9]{40}`:             true,
	`\b(ey[a-zA-Z0-9._-]+)\b`:  true,
	`\b([a-zA-Z0-9_-]{64,})\b`: true,
	`\d+\.\d+\.\d+`:            true,
	`\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`: true,
	`\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`:   true,
}

func loadPatternLines(raw, source string, into *[]secretPattern, seen map[string]struct{}) {
	var (
		currentRuleID string
		currentDesc   string
		ruleCounts    = make(map[string]int)
	)

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			currentDesc = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			currentRuleID = slugRuleID(currentDesc)
			continue
		}

		pat, ci := parsePatternLine(line)
		if pat == "" {
			continue
		}
		if skipBroadPatterns[pat] {
			continue
		}
		pat = normalizePattern(pat)
		compilePat := pat
		if ci && !strings.HasPrefix(compilePat, "(?i)") {
			compilePat = "(?i)" + compilePat
		}
		if _, dup := seen[compilePat]; dup {
			continue
		}
		re, err := regexp.Compile(compilePat)
		if err != nil {
			continue
		}
		seen[compilePat] = struct{}{}

		ruleID := assignRuleID(source, currentRuleID, currentDesc, compilePat, ruleCounts)
		kws, _ := extractKeywordsFromPattern(compilePat)
		*into = append(*into, secretPattern{
			re:              re,
			ruleID:          ruleID,
			description:     currentDesc,
			keywords:        kws,
			caseInsensitive: ci || strings.HasPrefix(compilePat, "(?i)"),
		})
	}
}

func assignRuleID(source, commentSlug, description, compilePat string, ruleCounts map[string]int) string {
	base := commentSlug
	if base == "" {
		h := sha256.Sum256([]byte(compilePat))
		base = fmt.Sprintf("%s-%x", source, h[:4])
	}
	ruleCounts[base]++
	if ruleCounts[base] == 1 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, ruleCounts[base])
}

func slugRuleID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.Index(s, "("); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func parsePatternLine(line string) (pat string, caseInsensitive bool) {
	switch {
	case strings.HasPrefix(line, "i|"):
		return strings.TrimPrefix(line, "i|"), true
	case strings.HasPrefix(line, "|"):
		return strings.TrimPrefix(line, "|"), false
	default:
		return line, false
	}
}

func normalizePattern(pat string) string {
	replacements := []struct{ old, new string }{
		{`[[:alnum:]]`, `[a-zA-Z0-9]`},
		{`[[:word:]]`, `\w`},
		{`[[:space:]]`, `\s`},
		{`\z`, `$`},
		{`\A`, `^`},
	}
	for _, r := range replacements {
		pat = strings.ReplaceAll(pat, r.old, r.new)
	}
	return pat
}

func loadAllSecretPatterns(coreRaw, curatedRaw, extraRaw string) []secretPattern {
	seen := make(map[string]struct{})
	var out []secretPattern
	loadPatternLines(coreRaw, "core", &out, seen)
	loadPatternLines(curatedRaw, "curated", &out, seen)
	loadPatternLines(extraRaw, "extra", &out, seen)
	return out
}

func findingsFromRegex(re *regexp.Regexp, data, source, ruleID string, lineStarts []int) []model.Finding {
	if re == nil {
		return nil
	}
	idxs := re.FindAllStringIndex(data, -1)
	if len(idxs) == 0 {
		return nil
	}
	if lineStarts == nil {
		lineStarts = buildLineStarts(data)
	}
	out := make([]model.Finding, 0, len(idxs))
	for _, idx := range idxs {
		loc := findingAt(data, lineStarts, source, ruleID, idx[0], idx[1])
		out = append(out, loc.toFinding())
	}
	return out
}

func (loc modelFindingLoc) toFinding() model.Finding {
	return model.Finding{
		Value:     loc.value,
		Source:    loc.source,
		RuleID:    loc.ruleID,
		StartLine: loc.startLine,
		EndLine:   loc.endLine,
		StartCol:  loc.startCol,
		EndCol:    loc.endCol,
		Snippet:   loc.snippet,
	}
}
