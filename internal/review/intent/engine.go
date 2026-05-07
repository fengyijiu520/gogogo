package intent

import (
	"regexp"
	"strings"

	"skill-scanner/internal/review"
)

type Engine struct{}

type declaredIntent struct {
	Network      bool
	File         bool
	Exec         bool
	Data         bool
	ExternalDeps bool
	Unsafe       bool
	Evidence     []string
}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Evaluate(description string, permissions []string, behavior review.BehaviorProfile) (float64, []review.IntentDiff) {
	score := 100.0
	diffs := make([]review.IntentDiff, 0)

	if strings.TrimSpace(description) == "" && len(permissions) == 0 {
		return score, diffs
	}

	intent := extractDeclaredIntent(description, permissions)
	if intent.Unsafe {
		diffs = append(diffs, review.IntentDiff{Type: "unsafe_declaration_prompt", Description: "技能声明中包含提示词注入、命令执行诱导或上下文污染语句；声明已按不可信文本隔离解析，未执行其中任何指令", Penalty: 20})
		score -= 20
	}

	if len(behavior.NetworkTargets) > 0 && !intent.Network {
		diffs = append(diffs, review.IntentDiff{Type: "unexpected_network", Description: "声明语义中未包含网络访问意图，但检测到外联目标", Penalty: 25})
		score -= 25
	}
	if len(behavior.FileTargets) > 0 && !intent.File {
		diffs = append(diffs, review.IntentDiff{Type: "unexpected_file", Description: "声明语义中未包含文件访问意图，但检测到文件访问行为", Penalty: 20})
		score -= 20
	}
	if len(behavior.ExecTargets) > 0 && !intent.Exec {
		diffs = append(diffs, review.IntentDiff{Type: "unexpected_exec", Description: "声明语义中未包含命令执行意图，但检测到命令执行行为", Penalty: 30})
		score -= 30
	}
	if len(behavior.CollectionIOCs) > 0 && !intent.Data {
		diffs = append(diffs, review.IntentDiff{Type: "unexpected_data_collection", Description: "声明语义中未包含数据收集或处理意图，但检测到数据收集/打包行为", Penalty: 25})
		score -= 25
	}
	if len(behavior.DownloadIOCs) > 0 && !intent.ExternalDeps {
		diffs = append(diffs, review.IntentDiff{Type: "unexpected_external_dependency", Description: "声明语义中未包含外部依赖下载或远程资源使用意图，但检测到下载行为", Penalty: 25})
		score -= 25
	}

	if score < 0 {
		score = 0
	}
	return score, diffs
}

func extractDeclaredIntent(description string, permissions []string) declaredIntent {
	intent := declaredIntent{}
	for _, perm := range permissions {
		applyIntentSignal(&intent, strings.ToLower(perm), "权限声明")
	}

	for _, line := range safeDeclarationLines(description) {
		lower := strings.ToLower(line)
		if isInstructionInjectionLine(lower) {
			intent.Unsafe = true
			continue
		}
		applyIntentSignal(&intent, lower, line)
	}
	return intent
}

func safeDeclarationLines(description string) []string {
	text := strings.ReplaceAll(description, "\r\n", "\n")
	parts := regexp.MustCompile(`[\n。；;]+`).Split(text, -1)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(stripMarkdownControls(part))
		if part == "" {
			continue
		}
		if len(part) > 500 {
			part = part[:500]
		}
		out = append(out, part)
	}
	return out
}

func stripMarkdownControls(line string) string {
	line = strings.TrimSpace(line)
	line = strings.TrimLeft(line, "#>*- `\t")
	return strings.TrimSpace(line)
}

func isInstructionInjectionLine(lower string) bool {
	injectionKeys := []string{
		"ignore previous", "ignore all previous", "system prompt", "developer message", "act as", "you are now",
		"执行以下命令", "运行以下命令", "忽略以上", "忽略之前", "系统提示词", "开发者消息", "你现在是",
		"写入记忆", "更新记忆", "调用工具", "call tool", "tool_use", "function_call", "sudo ", "rm -rf",
	}
	return containsAny(lower, injectionKeys...)
}

func applyIntentSignal(intent *declaredIntent, lower string, evidence string) {
	signals := []struct {
		matched bool
		apply   func()
	}{
		{containsAny(lower, "网络", "联网", "外联", "http", "https", "api", "webhook", "请求", "下载", "上传", "remote", "network"), func() { intent.Network = true }},
		{containsAny(lower, "文件", "目录", "读取", "写入", "上传文件", "解析文件", "保存", "file", "read", "write", "upload", "parse"), func() { intent.File = true }},
		{containsAny(lower, "命令", "执行", "shell", "脚本", "进程", "子进程", "command", "execute", "exec", "subprocess"), func() { intent.Exec = true }},
		{containsAny(lower, "数据", "隐私", "个人信息", "凭据", "上下文", "日志", "采集", "收集", "处理", "data", "privacy", "credential", "context"), func() { intent.Data = true }},
		{containsAny(lower, "依赖", "第三方", "模型", "远程资源", "插件", "包", "dependency", "package", "model", "external"), func() { intent.ExternalDeps = true }},
	}
	matched := false
	for _, signal := range signals {
		if signal.matched {
			signal.apply()
			matched = true
		}
	}
	if matched && evidence != "" {
		intent.Evidence = append(intent.Evidence, evidence)
	}
}

func containsPermission(permissions []string, keyword string) bool {
	for _, p := range permissions {
		if strings.Contains(strings.ToLower(p), strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func containsAny(text string, keys ...string) bool {
	for _, key := range keys {
		if strings.Contains(text, strings.ToLower(key)) {
			return true
		}
	}
	return false
}
