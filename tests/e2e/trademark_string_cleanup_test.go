package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

const (
	trademarkTokenVendor        = "Due" + "nde"
	trademarkTokenLegacyProduct = "Identity" + "Server"
)

func TestTrademarkStringsAreLimitedToAllowedE2E(t *testing.T) {
	t.Parallel()

	root := projectRoot(t)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			switch rel {
			case ".git", ".claude", ".agents", "_bmad-output":
				return filepath.SkipDir
			}
			return nil
		}

		contentBytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !utf8.Valid(contentBytes) {
			return nil
		}

		for lineNo, line := range strings.Split(string(contentBytes), "\n") {
			for _, token := range []string{trademarkTokenVendor, trademarkTokenLegacyProduct} {
				if !strings.Contains(line, token) {
					continue
				}
				if allowedTrademarkLine(rel, line, token) {
					continue
				}
				t.Fatalf("%s:%d contains disallowed trademark token %q: %s", rel, lineNo+1, token, line)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk release tree: %v", err)
	}
}

func allowedTrademarkLine(rel string, line string, token string) bool {
	if allowedE2ETrademarkAssertionLine(rel, line, token) {
		return true
	}
	if token != trademarkTokenLegacyProduct {
		return false
	}
	if rel == "NOTICE" || rel == "PROVENANCE.md" {
		return true
	}
	return strings.HasPrefix(strings.TrimSpace(line), "// From: "+trademarkTokenLegacyProduct+"4/")
}

func allowedE2ETrademarkAssertionLine(rel string, line string, token string) bool {
	trimmed := strings.TrimSpace(line)

	switch rel {
	case "tests/e2e/bucket_b_apache_copy_provenance_test.go":
		if token == trademarkTokenLegacyProduct {
			return strings.Contains(trimmed, trademarkTokenLegacyProduct+"4 Apache reference: tag") ||
				strings.Contains(trimmed, `"// From: `+trademarkTokenLegacyProduct+`4/"`)
		}
		return strings.Contains(trimmed, trademarkTokenVendor+"Software") ||
			strings.Contains(trimmed, trademarkTokenVendor+" 6.1.4") ||
			strings.Contains(trimmed, trademarkTokenVendor+" Software") ||
			strings.Contains(trimmed, `strings.Contains(line, "`+trademarkTokenVendor+`")`)
	case "tests/e2e/bucket_b_apache_correction_provenance_test.go":
		if token == trademarkTokenLegacyProduct {
			return strings.Contains(trimmed, `"`+trademarkTokenLegacyProduct+`4/"`)
		}
		return strings.Contains(trimmed, trademarkTokenVendor+" comparison tag: `6.1.4`")
	case "tests/e2e/gois_full_file_provenance_review_test.go":
		return token == trademarkTokenVendor &&
			strings.Contains(trimmed, "missing "+trademarkTokenVendor+" test structure check evidence")
	}

	return false
}
