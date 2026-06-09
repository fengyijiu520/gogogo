package ir

import (
	"strings"
)

// =============================================================================
// 注释过滤器
//
// 确保静态分析不检查注释内容。
// IR 层（Tree-sitter AST）天然跳过注释节点，
// 但字符串字面量、原始内容分析等场景仍需过滤。
// =============================================================================

// FilterComments 从源代码中移除注释行。
// 保留代码行，用于需要原始文本的分析场景。
func FilterComments(content string, language string) string {
	lines := strings.Split(content, "\n")
	var filtered []string

	for _, line := range lines {
		if !isCommentLine(line, language) {
			filtered = append(filtered, line)
		}
	}

	return strings.Join(filtered, "\n")
}

// FilterCommentLines 从行列表中移除注释行。
func FilterCommentLines(lines []string, language string) []string {
	var filtered []string
	for _, line := range lines {
		if !isCommentLine(line, language) {
			filtered = append(filtered, line)
		}
	}
	return filtered
}

// isCommentLine 判断一行是否为注释。
func isCommentLine(line, language string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}

	switch language {
	case "python":
		return isPythonComment(trimmed)
	case "ruby":
		return isRubyComment(trimmed)
	case "shell", "bash", "zsh":
		return isShellComment(trimmed)
	case "sql":
		return isSQLComment(trimmed)
	case "lua":
		return isLuaComment(trimmed)
	default:
		// 通用：C 风格注释
		return isCStyleComment(trimmed)
	}
}

func isPythonComment(line string) bool {
	return strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, `"""`) ||
		strings.HasPrefix(line, `'''`) ||
		strings.HasPrefix(line, `...`)
}

func isRubyComment(line string) bool {
	return strings.HasPrefix(line, "#")
}

func isShellComment(line string) bool {
	return strings.HasPrefix(line, "#")
}

func isSQLComment(line string) bool {
	return strings.HasPrefix(line, "--") ||
		strings.HasPrefix(line, "/*")
}

func isLuaComment(line string) bool {
	return strings.HasPrefix(line, "--")
}

func isCStyleComment(line string) bool {
	return strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "*/")
}

// FilterDocStrings 从 Python 代码中移除文档字符串。
func FilterDocStrings(content string) string {
	lines := strings.Split(content, "\n")
	var filtered []string
	inDocString := false
	docStringChar := ""

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if inDocString {
			if strings.Contains(trimmed, docStringChar) {
				inDocString = false
			}
			continue
		}

		if strings.HasPrefix(trimmed, `"""`) || strings.HasPrefix(trimmed, `'''`) {
			docStringChar = trimmed[:3]
			if strings.Count(trimmed, docStringChar) >= 2 {
				// 单行文档字符串
				continue
			}
			inDocString = true
			continue
		}

		filtered = append(filtered, line)
	}

	return strings.Join(filtered, "\n")
}

// IsInComment 检查指定行是否为注释（供报告标记使用）。
func IsInComment(line, language string) bool {
	return isCommentLine(line, language)
}
