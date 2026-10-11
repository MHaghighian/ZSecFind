package extractor

import (
	"strings"
	"unicode"

	aho "github.com/petar-dambovaliev/aho-corasick"
)

const minKeywordLen = 3

var keywordStop = map[string]bool{
	"http": true, "https": true, "http:": true, "https:": true,
	"www": true, "com": true, "org": true, "net": true, "api": true,
	"apps": true, "json": true, "xml": true, "html": true, "true": true,
	"false": true, "null": true,
	// Common source tokens that appear in almost every file
	"end": true, "name": true, "data": true, "type": true, "user": true,
	"file": true, "path": true, "host": true, "port": true, "from": true,
	"this": true, "self": true, "with": true, "into": true, "func": true,
	"var": true, "let": true, "const": true, "return": true, "function": true,
	"class": true, "string": true, "number": true, "object": true, "array": true,
	"value": true, "index": true, "error": true, "test": true, "main": true,
	"config": true, "default": true, "export": true, "import": true, "module": true,
}

// secretKeywordIndex maps Aho-Corasick pattern IDs to secretPatterns indices.
type secretKeywordIndex struct {
	ac             aho.AhoCorasick
	keywords       []string
	keywordToRules [][]int
	alwaysOn       []int
}

func buildSecretKeywordIndex(patterns []secretPattern) *secretKeywordIndex {
	kwSet := make(map[string][]int)
	var alwaysOn []int

	for i, sp := range patterns {
		kws := sp.keywords
		if len(kws) == 0 {
			alwaysOn = append(alwaysOn, i)
			continue
		}
		for _, kw := range kws {
			kw = strings.ToLower(kw)
			kwSet[kw] = append(kwSet[kw], i)
		}
	}

	keywords := make([]string, 0, len(kwSet))
	keywordToRules := make([][]int, 0, len(kwSet))
	for kw, rules := range kwSet {
		keywords = append(keywords, kw)
		keywordToRules = append(keywordToRules, rules)
	}

	idx := &secretKeywordIndex{
		keywords:       keywords,
		keywordToRules: keywordToRules,
		alwaysOn:       alwaysOn,
	}
	if len(keywords) == 0 {
		return idx
	}

	builder := aho.NewAhoCorasickBuilder(aho.Opts{
		AsciiCaseInsensitive: false,
		MatchOnlyWholeWords:  false,
		MatchKind:            aho.StandardMatch,
		DFA:                  true,
	})
	idx.ac = builder.Build(keywords)
	return idx
}

// eligibleSecretIndices returns secretPatterns indices that should run for data.
func (idx *secretKeywordIndex) eligibleSecretIndices(data string) []int {
	if idx == nil {
		n := make([]int, len(secretPatterns))
		for i := range n {
			n[i] = i
		}
		return n
	}

	seen := make([]bool, len(secretPatterns))
	var out []int
	add := func(i int) {
		if i < 0 || i >= len(seen) || seen[i] {
			return
		}
		seen[i] = true
		out = append(out, i)
	}
	for _, i := range idx.alwaysOn {
		add(i)
	}
	if len(idx.keywords) == 0 {
		return out
	}

	haystack := strings.ToLower(data)
	// FindAll skips nested overlaps (e.g. https:// hides https://discord).
	iter := idx.ac.IterOverlapping(haystack)
	for m := iter.Next(); m != nil; m = iter.Next() {
		pid := m.Pattern()
		if pid < 0 || pid >= len(idx.keywordToRules) {
			continue
		}
		for _, ri := range idx.keywordToRules[pid] {
			add(ri)
		}
	}
	return out
}

// extractKeywordsFromPattern returns high-signal literal keywords from a regex.
// Empty result means the rule must always run.
func extractKeywordsFromPattern(compilePat string) (keywords []string, caseInsensitive bool) {
	pat := compilePat
	if strings.HasPrefix(pat, "(?i)") {
		caseInsensitive = true
		pat = pat[4:]
	}

	runs := findLiteralRuns(pat)
	var out []string
	seen := make(map[string]struct{})
	for _, r := range runs {
		key := strings.ToLower(r)
		if !isUsefulKeyword(key) {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	if len(out) > 3 {
		sortByLenDesc(out)
		out = out[:3]
	}
	return out, caseInsensitive
}

func isUsefulKeyword(kw string) bool {
	if len(kw) < minKeywordLen {
		return false
	}
	if keywordStop[kw] {
		return false
	}
	if isAllDigits(kw) {
		return false
	}
	if isRepeatedChar(kw) {
		return false
	}
	// Require at least one letter — pure punctuation/digits are noisy.
	hasLetter := false
	for _, r := range kw {
		if unicode.IsLetter(r) {
			hasLetter = true
			break
		}
	}
	return hasLetter
}

func isRepeatedChar(s string) bool {
	if len(s) == 0 {
		return false
	}
	c := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != c {
			return false
		}
	}
	return true
}

func sortByLenDesc(ss []string) {
	for i := 0; i < len(ss); i++ {
		for j := i + 1; j < len(ss); j++ {
			if len(ss[j]) > len(ss[i]) {
				ss[i], ss[j] = ss[j], ss[i]
			}
		}
	}
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return len(s) > 0
}

// findLiteralRuns walks a regex pattern and collects maximal safe literal substrings.
func findLiteralRuns(pat string) []string {
	var runs []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		runs = append(runs, cur.String())
		cur.Reset()
	}

	i := 0
	for i < len(pat) {
		c := pat[i]
		switch c {
		case '\\':
			if i+1 >= len(pat) {
				flush()
				i++
				continue
			}
			n := pat[i+1]
			switch n {
			case 'x':
				flush()
				i += 4
				if i > len(pat) {
					i = len(pat)
				}
			case 'u', 'p', 'P', 'k':
				flush()
				i += 2
			case 'd', 'D', 'w', 'W', 's', 'S', 'b', 'B', 'A', 'z', 'Z', 'Q', 'E':
				flush()
				i += 2
			case 'n', 'r', 't', 'f', 'v', 'a', 'e':
				flush()
				i += 2
			default:
				cur.WriteByte(n)
				i += 2
			}
		case '[':
			flush()
			i++
			if i < len(pat) && pat[i] == '^' {
				i++
			}
			for i < len(pat) {
				if pat[i] == '\\' && i+1 < len(pat) {
					i += 2
					continue
				}
				if pat[i] == ']' {
					i++
					break
				}
				i++
			}
		case '{':
			flush()
			i++
			for i < len(pat) && pat[i] != '}' {
				i++
			}
			if i < len(pat) {
				i++ // skip }
			}
		case '(':
			flush()
			i++
			// Skip (?: (?= (?! (?<= (?<! (?i: etc.
			if i < len(pat) && pat[i] == '?' {
				i++
				for i < len(pat) && pat[i] != ':' && pat[i] != ')' && pat[i] != '<' &&
					pat[i] != '=' && pat[i] != '!' && (pat[i] < 'a' || pat[i] > 'z') {
					i++
				}
				// Consume flag letters and optional ':'
				for i < len(pat) && ((pat[i] >= 'a' && pat[i] <= 'z') || pat[i] == '-') {
					i++
				}
				if i < len(pat) && pat[i] == ':' {
					i++
				}
				if i < len(pat) && (pat[i] == '=' || pat[i] == '!' || pat[i] == '<') {
					// Lookahead/behind — skip rest of group content conservatively by depth
					depth := 1
					for i < len(pat) && depth > 0 {
						if pat[i] == '\\' && i+1 < len(pat) {
							i += 2
							continue
						}
						if pat[i] == '(' {
							depth++
						} else if pat[i] == ')' {
							depth--
						}
						i++
					}
				}
			}
		case ')', '|', '*', '+', '?', '^', '$', '.':
			flush()
			i++
		default:
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
				c == '_' || c == '-' || c == '/' || c == '@' || c == '=' || c == '+' || c == ':' {
				cur.WriteByte(c)
				i++
			} else if c == '#' || c == '%' || c == '&' || c == ';' || c == ',' || c == '~' {
				cur.WriteByte(c)
				i++
			} else {
				flush()
				i++
			}
		}
	}
	flush()
	return runs
}
