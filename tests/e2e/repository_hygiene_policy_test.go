package e2e_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

type forbiddenRepositoryText struct {
	name  string
	value string
}

type forbiddenRepositoryPattern struct {
	name    string
	pattern *regexp.Regexp
}

func TestRepositoryTrackedContentUsesNeutralTerminologyE2E(t *testing.T) {
	t.Parallel()

	forbiddenTexts := []forbiddenRepositoryText{
		{name: "clean" + "-room", value: "clean" + "-room"},
		{name: "Clean" + "Room", value: "Clean" + "Room"},
		{name: "buc" + "ket", value: "buc" + "ket"},
		{name: "Buc" + "ket", value: "Buc" + "ket"},
		{name: "wicket-provenance-" + "evidence", value: "wicket-provenance-" + "evidence"},
		{name: "Chinese isolation term", value: "\u51c0\u5ba4"},
		{name: "Chinese class A term", value: "\u6876 A"},
		{name: "Chinese class B term", value: "\u6876 B"},
		{name: "Chinese class C term", value: "\u6876 C"},
	}
	forbiddenPatterns := []forbiddenRepositoryPattern{
		{name: "story" + "-number", pattern: regexp.MustCompile("story" + "-[0-9]")},
		{name: "Story" + " number", pattern: regexp.MustCompile("Story" + " [0-9]")},
	}

	walkRepositoryTextFiles(t, func(rel string, content string) {
		for lineNo, line := range strings.Split(content, "\n") {
			for _, forbidden := range forbiddenTexts {
				if strings.Contains(line, forbidden.value) {
					t.Fatalf("%s:%d contains non-neutral repository term %q: %s", rel, lineNo+1, forbidden.name, line)
				}
			}
			for _, forbidden := range forbiddenPatterns {
				if forbidden.pattern.MatchString(line) {
					t.Fatalf("%s:%d contains non-neutral repository pattern %q: %s", rel, lineNo+1, forbidden.name, line)
				}
			}
		}
	})
}

func TestGoSourcesAvoidExternalContactMarkersE2E(t *testing.T) {
	t.Parallel()

	forbiddenTexts := []forbiddenRepositoryText{
		{name: "vendor name", value: "Due" + "nde"},
		{name: "vendor company", value: "Due" + "ndeSoftware"},
		{name: "vendor version", value: "6." + "1.4"},
		{name: "derived phrasing", value: "Based " + "on"},
		{name: "port phrasing", value: "Ported " + "from"},
	}

	for _, rel := range goFiles(t) {
		content := readProjectFile(t, rel)
		for lineNo, line := range strings.Split(content, "\n") {
			for _, forbidden := range forbiddenTexts {
				if strings.Contains(line, forbidden.value) {
					t.Fatalf("%s:%d contains source contact marker %q: %s", rel, lineNo+1, forbidden.name, line)
				}
			}
			if strings.Contains(line, "// From:") &&
				(strings.Contains(line, "Due"+"nde") || strings.Contains(line, "6."+"1.4") || strings.Contains(line, "v5")) {
				t.Fatalf("%s:%d contains forbidden source annotation: %s", rel, lineNo+1, line)
			}
		}
	}
}

func TestCommitMessagesUseNeutralTerminologyE2E(t *testing.T) {
	t.Parallel()

	log := runCommand(t, projectRoot(t), "git", "log", "--format=%B")
	forbiddenTexts := []forbiddenRepositoryText{
		{name: "story" + " 1-", value: "story" + " 1-"},
		{name: "class a file slug", value: "buc" + "ket-a"},
		{name: "class b file slug", value: "buc" + "ket-b"},
		{name: "class c file slug", value: "buc" + "ket-c"},
		{name: "clean" + "-room", value: "clean" + "-room"},
		{name: "legacy review file slug", value: "gois-full-file-provenance-review"},
		{name: "trademark cleanup file slug", value: "trademark-string-cleanup"},
		{name: "correction provenance file slug", value: "provenance-from-correction"},
	}

	for lineNo, line := range strings.Split(log, "\n") {
		for _, forbidden := range forbiddenTexts {
			if strings.Contains(line, forbidden.value) {
				t.Fatalf("git log line %d contains non-neutral commit message term %q: %s", lineNo+1, forbidden.name, line)
			}
		}
	}
}

func TestToolStateDirectoriesStayIgnoredE2E(t *testing.T) {
	t.Parallel()

	gitignore := readProjectFile(t, ".gitignore")
	for _, want := range []string{".cursor/", ".codegraph/"} {
		if !containsLine(gitignore, want) {
			t.Fatalf(".gitignore missing %s", want)
		}
	}
}

func walkRepositoryTextFiles(t *testing.T, visit func(rel string, content string)) {
	t.Helper()

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
			case ".git", ".claude", ".agents", ".rnix", ".codegraph", ".cursor", "_bmad-output":
				return filepath.SkipDir
			}
			return nil
		}

		switch rel {
		case "PROVENANCE.md", "NOTICE", "LICENSE":
			return nil
		}

		contentBytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !utf8.Valid(contentBytes) {
			return nil
		}

		visit(rel, string(contentBytes))
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository files: %v", err)
	}
}

func containsLine(content string, want string) bool {
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}
