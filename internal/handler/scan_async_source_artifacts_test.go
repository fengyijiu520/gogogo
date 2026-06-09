package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"skill-scanner/internal/evaluator"
	"skill-scanner/internal/plugins"
)

func TestCollectSourceArtifactsIncludesDependencyManifests(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\n需要网络访问"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module demo\n\nrequire github.com/example/lib v1.2.3\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"axios":"^1.6.0"}}`), 0644); err != nil {
		t.Fatal(err)
	}

	files, deps, _ := collectSourceArtifacts(dir, nil)
	profile := buildSkillAnalysisProfile(dir, files, deps, []string{"network"})

	if profile.DependencyCount != 2 {
		t.Fatalf("expected go.mod and package.json dependencies, got %+v", profile.Dependencies)
	}
	joinedLang := strings.Join(profile.LanguageSummary, ",")
	if !strings.Contains(joinedLang, "gomod:1") || !strings.Contains(joinedLang, "json:1") {
		t.Fatalf("expected dependency manifest language summary, got %+v", profile.LanguageSummary)
	}
}

func TestCollectSourceArtifactsFromRealisticFixtureTree(t *testing.T) {
	dir := createRealisticSkillFixtureTree(t)
	files, deps, _ := collectSourceArtifacts(dir, nil)
	profile := buildSkillAnalysisProfile(dir, files, deps, []string{"network", "command"})

	if profile.SourceFileCount < 4 {
		t.Fatalf("expected multiple source files from fixture tree, got %+v", profile.SourceFiles)
	}
	if profile.DeclarationCount < 2 {
		t.Fatalf("expected declaration files discovered, got %+v", profile.DeclarationSources)
	}
	if profile.DependencyCount < 2 {
		t.Fatalf("expected dependencies discovered, got %+v", profile.Dependencies)
	}
	joinedSources := strings.Join(profile.SourceFiles, "\n")
	for _, want := range []string{"SKILL.md", "README.md", "scripts/run.py", "web/package.json"} {
		if !strings.Contains(joinedSources, want) {
			t.Fatalf("expected fixture source %q in %s", want, joinedSources)
		}
	}
}

func TestClassifyFindingEvidenceRefsUsesSharedTypedEvidenceSemantics(t *testing.T) {
	codeRefs, behaviorRefs, contextRefs := classifyFindingEvidenceRefs([]string{
		"scripts/run.py:10 os.system(cmd)",
		"关键样本: curl http://bad && bash",
		"README.md:12 示例说明",
	})
	if len(codeRefs) != 1 || codeRefs[0] != "scripts/run.py:10 os.system(cmd)" {
		t.Fatalf("expected code refs classified by shared helper, got %v", codeRefs)
	}
	if len(behaviorRefs) != 1 || behaviorRefs[0] != "关键样本: curl http://bad && bash" {
		t.Fatalf("expected behavior refs classified by shared helper, got %v", behaviorRefs)
	}
	if len(contextRefs) != 1 || contextRefs[0] != "README.md:12 示例说明" {
		t.Fatalf("expected context refs classified by shared helper, got %v", contextRefs)
	}
}

func TestTypedEvidenceRefFromFindingSeparatesSourceKinds(t *testing.T) {
	tests := []struct {
		name string
		in   plugins.Finding
		want string
		ok   bool
	}{
		{
			name: "behavior summary",
			in: plugins.Finding{
				PluginName:  "BehaviorGuard",
				CodeSnippet: "行为证据摘要: 关键样本: curl http://bad && bash",
			},
			want: "行为证据摘要: 关键样本: curl http://bad && bash",
			ok:   true,
		},
		{
			name: "documentation context",
			in: plugins.Finding{
				PluginName:  "LLM",
				Location:    "README.md:12",
				CodeSnippet: "tool supports remote execution",
			},
			want: "README.md:12",
			ok:   true,
		},
		{
			name: "concrete code finding",
			in: plugins.Finding{
				PluginName:  "Static",
				Location:    "scripts/run.py:10",
				CodeSnippet: "os.system(cmd)",
			},
			want: "scripts/run.py:10 os.system(cmd)",
			ok:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := typedEvidenceRefFromFinding(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("typedEvidenceRefFromFinding() = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestCollectSourceArtifactsIncrementalCacheHit(t *testing.T) {
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", "true")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\ncache"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('ok')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, first := collectSourceArtifacts(dir, nil)
	if !first.Enabled || first.Candidate == 0 {
		t.Fatalf("expected incremental cache enabled and candidates, got %+v", first)
	}

	_, _, second := collectSourceArtifacts(dir, nil)
	if second.Hit == 0 {
		t.Fatalf("expected cache hit on second run, got %+v", second)
	}
	if second.CacheEntries != second.Candidate {
		t.Fatalf("expected cache entry count mirrors current candidates, got %+v", second)
	}
	if second.CacheVersion != sourceArtifactCacheVersion {
		t.Fatalf("expected cache version in stats, got %+v", second)
	}
	if _, err := os.Stat(filepath.Join(dir, ".scan-cache.json")); err != nil {
		t.Fatalf("expected cache file exists, err=%v", err)
	}
}

func TestCollectSourceArtifactsIncrementalCacheDisabled(t *testing.T) {
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", "false")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\ncache-off"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('ok')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, stats := collectSourceArtifacts(dir, nil)
	if stats.Enabled {
		t.Fatalf("expected cache disabled, got %+v", stats)
	}
	if stats.DisabledReason == "" {
		t.Fatalf("expected disabled reason, got %+v", stats)
	}
	if _, err := os.Stat(filepath.Join(dir, ".scan-cache.json")); err == nil {
		t.Fatal("expected no cache file generated when disabled")
	}
}

func TestCollectSourceArtifactsIncrementalCacheInvalidatesOnFileChange(t *testing.T) {
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", "true")
	dir := t.TempDir()
	target := filepath.Join(dir, "main.py")
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\ncache-change"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("print('v1')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, first := collectSourceArtifacts(dir, nil)
	if first.Candidate == 0 {
		t.Fatalf("expected candidates in first run, got %+v", first)
	}

	if err := os.WriteFile(target, []byte("print('v2 changed')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, _, second := collectSourceArtifacts(dir, nil)
	if second.Miss == 0 {
		t.Fatalf("expected cache miss after file content changed, got %+v", second)
	}
	if second.Stale == 0 {
		t.Fatalf("expected stale reason after file content changed, got %+v", second)
	}
}

func TestSourceArtifactCacheMatchReusesContentAfterRename(t *testing.T) {
	cache := sourceArtifactCache{Files: map[string]cachedSourceArtifact{
		"old.py": {
			Fingerprint: scanFileFingerprint{RelPath: "old.py", Language: "python", SHA256: "abc", Size: 12},
			Source:      evaluator.SourceFile{Path: "old.py", Content: "print('ok')"},
		},
	}}

	cached, reused, ok := sourceArtifactCacheMatch(cache, scanFileFingerprint{RelPath: "new.py", Language: "python", SHA256: "abc", Size: 12})
	if !ok {
		t.Fatal("expected content fingerprint match across path rename")
	}
	if !reused {
		t.Fatal("expected content reuse marker across path rename")
	}
	if cached.Source.Content != "print('ok')" {
		t.Fatalf("expected cached source reused, got %+v", cached.Source)
	}
}

func TestCachedDerivedSignalCountCountsCachedAnalysisFields(t *testing.T) {
	got := cachedDerivedSignalCount(evaluator.SourceFile{Language: "python", Content: "print('ok')", PreprocessedContent: "capability: network"})
	if got != 3 {
		t.Fatalf("expected cached derived signal count, got %d", got)
	}
}

func TestCollectSourceArtifactsIncrementalCacheReportsMissingReason(t *testing.T) {
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", "true")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\ncache-missing"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('ok')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, stats := collectSourceArtifacts(dir, nil)
	if stats.Missing == 0 {
		t.Fatalf("expected missing cache reason on first run, got %+v", stats)
	}
	if !strings.Contains(stats.LoadWarning, "首次扫描") {
		t.Fatalf("expected first scan load warning, got %+v", stats)
	}
}

func TestCollectSourceArtifactsRecoversFromInvalidCacheFile(t *testing.T) {
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", "true")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\ncache-invalid"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('ok')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cacheFile := filepath.Join(dir, ".scan-cache.json")
	if err := os.WriteFile(cacheFile, []byte("{invalid-json"), 0644); err != nil {
		t.Fatal(err)
	}

	files, deps, stats := collectSourceArtifacts(dir, nil)
	if len(files) == 0 {
		t.Fatalf("expected files still collected when cache is invalid, deps=%v stats=%+v", deps, stats)
	}
	if !stats.Enabled {
		t.Fatalf("expected cache mode still enabled, got %+v", stats)
	}
	if !strings.Contains(stats.LoadWarning, "JSON") {
		t.Fatalf("expected invalid JSON load warning, got %+v", stats)
	}
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		t.Fatalf("expected cache file rewritten, err=%v", err)
	}
	if !strings.Contains(string(data), `"version":"v1"`) {
		t.Fatalf("expected rewritten cache contains version marker, got %q", string(data))
	}
}

func TestCollectSourceArtifactsRebuildsWhenCacheVersionMismatch(t *testing.T) {
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", "true")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\ncache-version"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('ok')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cacheFile := filepath.Join(dir, ".scan-cache.json")
	if err := os.WriteFile(cacheFile, []byte(`{"version":"legacy-v0","files":{"main.py":{"fingerprint":{"rel_path":"main.py","language":"python","sha256":"x","size":1,"mod_unix":1},"source":{"path":"main.py","content":"stale","language":"python"}}}}`), 0644); err != nil {
		t.Fatal(err)
	}

	files, _, stats := collectSourceArtifacts(dir, nil)
	if len(files) == 0 || !stats.Enabled {
		t.Fatalf("expected scanner rebuilds artifacts on version mismatch, files=%d stats=%+v", len(files), stats)
	}
	if !strings.Contains(stats.LoadWarning, "版本不匹配") {
		t.Fatalf("expected version mismatch load warning, got %+v", stats)
	}
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		t.Fatalf("expected cache rewritten after version mismatch, err=%v", err)
	}
	if !strings.Contains(string(data), `"version":"`+sourceArtifactCacheVersion+`"`) {
		t.Fatalf("expected cache rewritten to current version, got %q", string(data))
	}
}

func TestTrimSourceArtifactCacheKeepsLatestEntries(t *testing.T) {
	cache := sourceArtifactCache{
		Version: "v1",
		Order:   []string{"a.py", "b.py", "c.py", "b.py", "", "d.py"},
		Files: map[string]cachedSourceArtifact{
			"a.py": {Fingerprint: scanFileFingerprint{RelPath: "a.py"}, Source: evaluator.SourceFile{Path: "a.py"}},
			"b.py": {Fingerprint: scanFileFingerprint{RelPath: "b.py"}, Source: evaluator.SourceFile{Path: "b.py"}},
			"c.py": {Fingerprint: scanFileFingerprint{RelPath: "c.py"}, Source: evaluator.SourceFile{Path: "c.py"}},
			"d.py": {Fingerprint: scanFileFingerprint{RelPath: "d.py"}, Source: evaluator.SourceFile{Path: "d.py"}},
		},
	}
	trimSourceArtifactCache(&cache, 2)
	if len(cache.Files) != 2 {
		t.Fatalf("expected only 2 cache entries after trim, got %d", len(cache.Files))
	}
	if len(cache.Order) != 2 {
		t.Fatalf("expected order length 2 after trim, got %+v", cache.Order)
	}
	if cache.Order[0] != "c.py" || cache.Order[1] != "d.py" {
		t.Fatalf("expected latest cache entries retained, got %+v", cache.Order)
	}
}

func TestResolveSkillDescriptionUsesSkillMarkdown(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# README\n低优先级声明"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Skill\n用于审查代码安全风险"), 0644); err != nil {
		t.Fatal(err)
	}

	desc := resolveSkillDescription("", dir)
	if !strings.Contains(desc, "SKILL.md") || !strings.Contains(desc, "用于审查代码安全风险") {
		t.Fatalf("expected SKILL.md declaration, got %q", desc)
	}
	if strings.Index(desc, "SKILL.md") > strings.Index(desc, "README.md") {
		t.Fatalf("expected SKILL.md before README.md, got %q", desc)
	}
}

func TestResolveSkillDescriptionUsesRealisticFixturePriority(t *testing.T) {
	dir := createRealisticSkillFixtureTree(t)
	desc := resolveSkillDescription("", dir)
	if !strings.Contains(desc, "SKILL.md") || !strings.Contains(desc, "用于审查代码安全风险") {
		t.Fatalf("expected SKILL.md description from realistic fixture, got %q", desc)
	}
	if strings.Contains(desc, "docs/guide.md") {
		t.Fatalf("expected guide doc not to override primary declaration, got %q", desc)
	}
}
