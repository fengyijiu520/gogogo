package sandbox

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"skill-scanner/internal/logx"
)

// SkillManifest 技能清单信息（从 SKILL.md 解析）
type SkillManifest struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Version      string   `json:"version"`
	Author       string   `json:"author"`
	Scripts      []string `json:"scripts"`       // 声明的脚本路径
	Dependencies []string `json:"dependencies"`   // 声明的依赖
	Permissions  []string `json:"permissions"`    // 声明的权限
	EntryPoints  []string `json:"entry_points"`   // 声明的入口点
	RawContent   string   `json:"raw_content"`    // 原始内容
}

// parseSkillManifest 解析 SKILL.md 文件
func parseSkillManifest(scanPath string) *SkillManifest {
	// 尝试多种可能的文件名
	candidates := []string{"SKILL.md", "skill.md", "SKILL.MD", "Skill.md"}
	var data []byte
	var found string
	for _, name := range candidates {
		path := filepath.Join(scanPath, name)
		d, err := os.ReadFile(path)
		if err == nil {
			data = d
			found = name
			break
		}
	}
	if data == nil {
		return nil
	}

	logx.With("component", "sandbox_probe").Info("found skill manifest", "file", found)

	content := string(data)
	manifest := &SkillManifest{RawContent: content}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// 解析标题作为名称
		if strings.HasPrefix(trimmed, "# ") && manifest.Name == "" {
			manifest.Name = strings.TrimSpace(strings.TrimPrefix(trimmed, "# "))
			continue
		}

		// 解析 key: value 格式
		if strings.Contains(trimmed, ":") && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "-") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(strings.ToLower(parts[0]))
				value := strings.TrimSpace(parts[1])
				switch key {
				case "name":
					if manifest.Name == "" {
						manifest.Name = value
					}
				case "description", "desc":
					manifest.Description = value
				case "version":
					manifest.Version = value
				case "author":
					manifest.Author = value
				case "entry", "entrypoint", "entry_point", "main":
					manifest.EntryPoints = append(manifest.EntryPoints, value)
				}
			}
		}

		// 解析脚本引用（scripts/xxx 或 ./scripts/xxx）
		scriptRe := regexp.MustCompile(`(?:scripts?[/\\][^\s"']+|(?:\./)?scripts?[/\\][^\s"']+)`)
		for _, m := range scriptRe.FindAllString(trimmed, -1) {
			cleaned := strings.Trim(m, "`\"',.)")
			if cleaned != "" {
				manifest.Scripts = append(manifest.Scripts, cleaned)
			}
		}

		// 解析代码块中的命令
		if strings.HasPrefix(trimmed, "```") {
			// 代码块标记，跳过
			continue
		}
	}

	// 解析代码块中的脚本路径
	codeBlockRe := regexp.MustCompile("(?s)```(?:bash|sh|shell)?\n(.*?)```")
	for _, match := range codeBlockRe.FindAllStringSubmatch(content, -1) {
		block := match[1]
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			// 跳过注释和空行
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// 提取脚本路径引用
			if strings.Contains(line, "scripts/") || strings.Contains(line, "./scripts/") {
				scriptRe := regexp.MustCompile(`(?:\./)?scripts/[^\s"']+`)
				for _, m := range scriptRe.FindAllString(line, -1) {
					cleaned := strings.Trim(m, "`\"',.)")
					if cleaned != "" {
						manifest.Scripts = append(manifest.Scripts, cleaned)
					}
				}
			}
		}
	}

	// 去重
	manifest.Scripts = uniqueStrings(manifest.Scripts)
	manifest.EntryPoints = uniqueStrings(manifest.EntryPoints)

	return manifest
}

// discoverSkillEntrypoints 增强版入口点发现，包含 SKILL.md 解析
func discoverSkillEntrypoints(scanPath string) []entrypointCandidate {
	var candidates []entrypointCandidate

	// 1. 解析 SKILL.md 获取声明的入口点
	manifest := parseSkillManifest(scanPath)
	if manifest != nil {
		// 从声明的入口点添加
		for _, ep := range manifest.EntryPoints {
			ep = strings.TrimSpace(ep)
			if ep != "" && pathExists(filepath.Join(scanPath, ep)) {
				candidates = append(candidates, entrypointCandidate{
					path: ep,
					name: "manifest-" + buildEntrypointScenarioName(ep),
				})
			}
		}
		// 从声明的脚本路径添加
		for _, script := range manifest.Scripts {
			script = strings.TrimSpace(script)
			if script != "" && pathExists(filepath.Join(scanPath, script)) {
				candidates = append(candidates, entrypointCandidate{
					path: script,
					name: "skill-script-" + buildEntrypointScenarioName(script),
				})
			}
		}
	}

	// 2. 扫描 scripts/ 目录
	scriptDir := filepath.Join(scanPath, "scripts")
	if entries, err := os.ReadDir(scriptDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			ext := strings.ToLower(filepath.Ext(name))
			if ext == ".py" || ext == ".js" || ext == ".ts" || ext == ".sh" || ext == ".go" {
				rel := "scripts/" + name
				candidates = append(candidates, entrypointCandidate{
					path: rel,
					name: "scripts-dir-" + buildEntrypointScenarioName(rel),
				})
			}
		}
	}

	// 3. 标准入口文件（与现有 discoverExecutionEntrypoints 合并）
	standardEntrypoints := discoverExecutionEntrypoints(scanPath)
	candidates = append(candidates, standardEntrypoints...)

	// 4. Go 项目入口（cmd/ 目录）
	cmdDir := filepath.Join(scanPath, "cmd")
	if entries, err := os.ReadDir(cmdDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			mainGo := filepath.Join("cmd", entry.Name(), "main.go")
			if pathExists(filepath.Join(scanPath, mainGo)) {
				candidates = append(candidates, entrypointCandidate{
					path:    mainGo,
					name:    "go-cmd-" + entry.Name(),
					command: "go",
					args:    []string{"run", mainGo},
				})
			}
		}
	}

	// 5. 根目录 main.go
	if pathExists(filepath.Join(scanPath, "main.go")) {
		candidates = append(candidates, entrypointCandidate{
			path:    "main.go",
			name:    "go-main",
			command: "go",
			args:    []string{"run", "main.go"},
		})
	}

	// 6. Makefile 入口
	if pathExists(filepath.Join(scanPath, "Makefile")) {
		candidates = append(candidates, entrypointCandidate{
			path:    "Makefile",
			name:    "makefile",
			command: "make",
			args:    []string{},
		})
	}

	return uniqueEntrypointCandidates(candidates)
}
