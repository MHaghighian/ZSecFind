package extractor

import (
	"regexp"
	"sync"

	"github.com/l4tr0d3ctism/ZSecFind/patterns"
)

var (
	staticExtensions []string

	secretPatterns []secretPattern
	secretIndex    *secretKeywordIndex

	reSFZ            *regexp.Regexp
	reMobile         *regexp.Regexp
	reMail           *regexp.Regexp
	reIP             *regexp.Regexp
	reIPPort         *regexp.Regexp
	reDomain         *regexp.Regexp
	rePath           *regexp.Regexp
	reIncompletePath *regexp.Regexp
	reURL            *regexp.Regexp
	reJWT            *regexp.Regexp
	reAlgorithm      *regexp.Regexp
	reIPInURL        *regexp.Regexp
	reIPPortInURL    *regexp.Regexp
	reDomainInURL    *regexp.Regexp

	initOnce sync.Once
)

func initPatterns() {
	initOnce.Do(func() {
		tld := patterns.TLD()
		staticExtensions = patterns.StaticExtensions()

		reSFZ = mustCategoryPattern("sfz", tld)
		reMobile = mustCategoryPattern("mobile", tld)
		reMail = mustCategoryPattern("mail", tld)
		reIP = mustCategoryPattern("ip", tld)
		reIPPort = mustCategoryPattern("ip_port", tld)
		reDomain = mustCategoryPattern("domain", tld)
		rePath = mustCategoryPattern("path", tld)
		reIncompletePath = mustCategoryPattern("incomplete_path", tld)
		reURL = mustCategoryPattern("url", tld)
		reJWT = mustCategoryPattern("jwt", tld)
		reAlgorithm = mustCategoryPattern("algorithm", tld)
		reIPInURL = mustCategoryPattern("ip_in_url", tld)
		reIPPortInURL = reIPPort
		reDomainInURL = mustCategoryPattern("domain_in_url", tld)

		core, curated, extra := patterns.Secrets()
		secretPatterns = loadAllSecretPatterns(core, curated, extra)
		secretIndex = buildSecretKeywordIndex(secretPatterns)
	})
}

func mustCategoryPattern(name, tld string) *regexp.Regexp {
	pat := patterns.CategoryPattern(name, tld)
	re, err := regexp.Compile(pat)
	if err != nil {
		panic("patterns/categories/" + name + ".txt: " + err.Error())
	}
	return re
}
