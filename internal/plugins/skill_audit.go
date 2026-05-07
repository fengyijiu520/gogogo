package plugins

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SkillAuditDetector performs an offline Agent Skill consistency audit for the
// plugin fallback path used when the semantic engine is unavailable.
type SkillAuditDetector struct{}

func NewSkillAuditDetector() *SkillAuditDetector {
	return &SkillAuditDetector{}
}

func (p *SkillAuditDetector) Name() string {
	return "SkillAuditDetector"
}

func (p *SkillAuditDetector) Execute(ctx context.Context, scanPath string) ([]Finding, error) {
	if !hasSkillManifest(scanPath) {
		return nil, nil
	}

	declaredText := collectSkillManifestText(scanPath)
	declaresNetwork := pluginContainsAny(declaredText, "network", "http", "api", "url", "web", "download", "fetch", "requests", "联网", "网络", "接口", "外部", "下载")
	declaresCommand := pluginContainsAny(declaredText, "command", "shell", "exec", "subprocess", "terminal", "命令", "终端", "执行脚本", "运行脚本")
	declaresSensitiveFile := pluginContainsAny(declaredText, "credential", "token", "secret", "ssh", "env", "home", "file", "凭据", "密钥", "令牌", "环境变量", "文件")
	declaresDestructive := pluginContainsAny(declaredText, "delete", "remove", "cleanup", "drop", "truncate", "删除", "清理", "移除", "销毁")

	patterns := []struct {
		declared bool
		severity string
		desc     string
		re       *regexp.Regexp
	}{
		{false, "高风险", "Skill 脚本包含反弹 Shell 或远程交互式控制逻辑，属于明显恶意行为。", regexp.MustCompile(`(?i)(bash\s+-i\s+>&\s*/dev/tcp|nc\s+-e\s+|socket\.socket|reverse[_-]?shell)`)},
		{false, "高风险", "Skill 脚本包含挖矿、C2 或持久化后门特征，属于明显恶意行为。", regexp.MustCompile(`(?i)(xmrig|stratum\+tcp|coinhive|crontab\s+-|authorized_keys|launchctl|systemctl\s+enable|command\s*and\s*control|\bc2\b)`)},
		{declaresSensitiveFile, "高风险", "声明未提及敏感凭据或用户配置访问，但 Skill 脚本读取了相关敏感位置。", regexp.MustCompile(`(?i)(os\.environ|getenv\(|\.env\b|\.ssh|id_rsa|credentials?\.|token\.|secret\.|/home/|~/|/Users/)`)},
		{declaresNetwork, "高风险", "声明未提及网络访问，但 Skill 脚本包含外联、下载或上传能力。", regexp.MustCompile(`(?i)(requests\.(get|post|put)|fetch\(|axios\.|http\.(Get|Post|NewRequest)|urllib\.request|curl\s+|wget\s+|https?://)`)},
		{declaresCommand, "高风险", "声明未提及命令执行，但 Skill 脚本包含 shell、子进程或动态代码执行能力。", regexp.MustCompile(`(?i)(subprocess\.|os\.system\(|exec\.Command\(|child_process\.|Runtime\.getRuntime\(\)\.exec|eval\(|exec\(|popen\()`)},
		{declaresDestructive, "高风险", "声明未提及破坏性操作，但 Skill 脚本包含删除、清空或不可逆修改能力。", regexp.MustCompile(`(?i)(rm\s+-rf|os\.remove|os\.unlink|shutil\.rmtree|fs\.rm|delete\s+from|drop\s+table|truncate\s+table)`)},
	}

	var findings []Finding
	err := filepath.Walk(scanPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil || info.IsDir() || ctx.Err() != nil || !isPluginSkillScript(scanPath, path) {
			return ctx.Err()
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
				continue
			}
			for _, pattern := range patterns {
				if pattern.declared || !pattern.re.MatchString(trimmed) {
					continue
				}
				findings = append(findings, Finding{
					PluginName:  p.Name(),
					RuleID:      "V7-006",
					Severity:    pattern.severity,
					Title:       "Agent Skill 声明与实际行为不一致",
					Description: pattern.desc,
					Location:    fmt.Sprintf("%s:%d", filepath.Base(path), i+1),
					CodeSnippet: pluginCodeContext(lines, i, 2),
				})
			}
		}
		return nil
	})
	if err != nil && err != context.Canceled {
		return findings, err
	}
	return findings, nil
}

func hasSkillManifest(scanPath string) bool {
	_, err := os.Stat(filepath.Join(scanPath, "SKILL.md"))
	return err == nil
}

func collectSkillManifestText(scanPath string) string {
	data, err := os.ReadFile(filepath.Join(scanPath, "SKILL.md"))
	if err != nil {
		return ""
	}
	return strings.ToLower(string(data))
}

func isPluginSkillScript(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	rel = strings.ToLower(filepath.ToSlash(rel))
	if !strings.HasPrefix(rel, "scripts/") {
		return false
	}
	switch filepath.Ext(rel) {
	case ".go", ".js", ".ts", ".py", ".sh", ".rb", ".php":
		return true
	default:
		return false
	}
}

func pluginContainsAny(text string, keys ...string) bool {
	text = strings.ToLower(text)
	for _, key := range keys {
		if strings.Contains(text, strings.ToLower(key)) {
			return true
		}
	}
	return false
}

func pluginCodeContext(lines []string, idx, radius int) string {
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	var builder strings.Builder
	for i := start; i < end; i++ {
		prefix := "  "
		if i == idx {
			prefix = "> "
		}
		builder.WriteString(fmt.Sprintf("%s%4d | %s\n", prefix, i+1, lines[i]))
	}
	return builder.String()
}
