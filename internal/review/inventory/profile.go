package inventory

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"skill-scanner/internal/evaluator"
)

const DefaultAnalysisMode = "语义模型 + LLM 意图分析 + 沙箱行为分析 + V7 规则引擎全链路评估"

type Profile struct {
	DeclarationSources []string `json:"declaration_sources"`
	SourceFiles        []string `json:"source_files"`
	Dependencies       []string `json:"dependencies"`
	Permissions        []string `json:"permissions"`
	AnalysisMode       string   `json:"analysis_mode"`
	FileCount          int      `json:"file_count"`
	SourceFileCount    int      `json:"source_file_count"`
	DeclarationCount   int      `json:"declaration_count"`
	DependencyCount    int      `json:"dependency_count"`
	LanguageSummary    []string `json:"language_summary"`
	CapabilitySignals  []string `json:"capability_signals"`
}

func BuildProfile(scanPath string, files []evaluator.SourceFile, dependencies []evaluator.Dependency, permissions []string) Profile {
	profile := Profile{
		Permissions:  append([]string{}, permissions...),
		AnalysisMode: DefaultAnalysisMode,
	}
	languageCounts := make(map[string]int)
	for _, file := range files {
		rel := DisplayRelPath(scanPath, file.Path)
		profile.SourceFiles = append(profile.SourceFiles, rel)
		if strings.TrimSpace(file.Language) != "" {
			languageCounts[file.Language]++
		}
		base := strings.ToLower(filepath.Base(file.Path))
		switch base {
		case "skill.md", "readme.md", "description.md", "manifest.md":
			profile.DeclarationSources = append(profile.DeclarationSources, rel)
		}
		profile.CapabilitySignals = append(profile.CapabilitySignals, InferCapabilitySignals(file.Content)...)
	}
	for _, dep := range dependencies {
		item := strings.TrimSpace(dep.Name)
		if strings.TrimSpace(dep.Version) != "" {
			item += "@" + strings.TrimSpace(dep.Version)
		}
		if item != "" {
			profile.Dependencies = append(profile.Dependencies, item)
		}
	}
	profile.FileCount = len(files)
	profile.SourceFileCount = len(profile.SourceFiles)
	profile.DeclarationCount = len(profile.DeclarationSources)
	profile.DependencyCount = len(profile.Dependencies)
	for lang, count := range languageCounts {
		profile.LanguageSummary = append(profile.LanguageSummary, fmt.Sprintf("%s:%d", lang, count))
	}
	profile.CapabilitySignals = UniqueStrings(profile.CapabilitySignals)
	sort.Strings(profile.DeclarationSources)
	sort.Strings(profile.SourceFiles)
	sort.Strings(profile.Dependencies)
	sort.Strings(profile.Permissions)
	sort.Strings(profile.LanguageSummary)
	sort.Strings(profile.CapabilitySignals)
	return profile
}

func InferCapabilitySignals(content string) []string {
	lower := strings.ToLower(content)
	var signals []string
	checks := []struct {
		label string
		terms []string
	}{
		{label: "网络访问", terms: []string{"http://", "https://", "requests.", "fetch(", "axios", "net/http"}},
		{label: "命令执行", terms: []string{"exec(", "exec.command", "subprocess", "os.system", "child_process", "spawn("}},
		{label: "文件读写", terms: []string{"readfile", "writefile", "os.read", "os.write", "open(", "fs."}},
		{label: "敏感凭据访问", terms: []string{"api_key", "secret", "token", "password", ".env", "credential"}},
		{label: "持久化或计划任务", terms: []string{"crontab", "systemd", "launchctl", "startup", "autorun"}},
	}
	for _, check := range checks {
		for _, term := range check.terms {
			if strings.Contains(lower, term) {
				signals = append(signals, check.label)
				break
			}
		}
	}
	return signals
}

func UniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func LimitList(items []string, limit int) []string {
	if limit <= 0 {
		return append([]string{}, items...)
	}
	if len(items) <= limit {
		return append([]string{}, items...)
	}
	return append([]string{}, items[:limit]...)
}

func DisplayRelPath(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil && rel != "." {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(filepath.Base(path))
}
