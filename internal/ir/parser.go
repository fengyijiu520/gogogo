package ir

import (
	"fmt"
	"path/filepath"
	"strings"
)

// =============================================================================
// 解析器注册表
// =============================================================================

var parsers = map[string]Parser{}
var extParsers = map[string]Parser{}

// RegisterParser 注册一个语言解析器。
func RegisterParser(p Parser) {
	lang := strings.ToLower(p.Language())
	parsers[lang] = p
	for _, ext := range p.Extensions() {
		extParsers[strings.ToLower(ext)] = p
	}
}

// GetParser 根据语言标识获取解析器。
func GetParser(language string) (Parser, bool) {
	p, ok := parsers[strings.ToLower(language)]
	return p, ok
}

// GetParserByExt 根据文件扩展名获取解析器。
func GetParserByExt(ext string) (Parser, bool) {
	p, ok := extParsers[strings.ToLower(ext)]
	return p, ok
}

// GetParserForFile 根据文件路径获取解析器。
func GetParserForFile(path string) (Parser, bool) {
	ext := filepath.Ext(path)
	return GetParserByExt(ext)
}

// SupportedLanguages 返回所有已注册的语言。
func SupportedLanguages() []string {
	langs := make([]string, 0, len(parsers))
	for lang := range parsers {
		langs = append(langs, lang)
	}
	return langs
}

// ParseFile 使用合适的解析器解析源文件。
// 如果没有对应的解析器，返回降级的 File（仅包含原始文本）。
func ParseFile(path string, content string, language string) *File {
	var parser Parser
	var ok bool

	if language != "" {
		parser, ok = GetParser(language)
	}
	if !ok {
		parser, ok = GetParserForFile(path)
	}

	if ok {
		file, err := parser.Parse(path, content)
		if err == nil {
			return file
		}
		// 解析失败，降级
		return &File{
			Path:       path,
			Language:   language,
			RawContent: content,
			ParseError: err.Error(),
		}
	}

	// 没有对应解析器，返回纯文本 File
	return &File{
		Path:       path,
		Language:   language,
		RawContent: content,
		ParseError: fmt.Sprintf("no parser for language: %s", language),
	}
}

// =============================================================================
// 通用解析工具
// =============================================================================

// ExtractCallExprsFromText 从原始文本中提取调用表达式（正则降级方案）。
// 当 AST 解析失败时使用此方法。
func ExtractCallExprsFromText(content string, path string) []CallExpr {
	var calls []CallExpr
	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// 简单的括号匹配：找 funcName(...) 形式
		extracted := extractCallsFromLine(line, lineNum+1)
		calls = append(calls, extracted...)
	}
	return calls
}

// extractCallsFromLine 从单行中提取调用表达式。
func extractCallsFromLine(line string, lineNum int) []CallExpr {
	var calls []CallExpr
	// 查找所有 identifier(... 或 identifier.method(... 模式
	i := 0
	for i < len(line) {
		// 找到 '('
		parenIdx := strings.Index(line[i:], "(")
		if parenIdx < 0 {
			break
		}
		parenIdx += i

		// 往前找函数名
		funcEnd := parenIdx
		funcStart := funcEnd - 1
		for funcStart >= 0 && isIdentChar(line[funcStart]) {
			funcStart--
		}
		funcStart++

		if funcStart == funcEnd {
			i = parenIdx + 1
			continue
		}

		funcName := line[funcStart:funcEnd]
		// 也检查前面是否有 receiver.
		dotIdx := funcStart - 1
		for dotIdx >= 0 && line[dotIdx] == ' ' {
			dotIdx--
		}
		if dotIdx >= 0 && line[dotIdx] == '.' {
			receiverEnd := dotIdx
			receiverStart := receiverEnd - 1
			for receiverStart >= 0 && isIdentChar(line[receiverStart]) {
				receiverStart--
			}
			receiverStart++
			if receiverStart < receiverEnd {
				funcName = line[receiverStart:receiverEnd] + "." + funcName
			}
		}

		// 找到匹配的 ')'
		argStart := parenIdx + 1
		depth := 1
		j := argStart
		for j < len(line) && depth > 0 {
			switch line[j] {
			case '(':
				depth++
			case ')':
				depth--
			}
			j++
		}

		if depth == 0 {
			argStr := line[argStart : j-1]
			args := splitArgs(argStr)
			calls = append(calls, CallExpr{
				FuncName: funcName,
				Line:     lineNum,
				Args:     args,
			})
		}

		i = j
	}
	return calls
}

// isIdentChar 判断字符是否为标识符字符。
func isIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.'
}

// splitArgs 简单分割调用参数。
func splitArgs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var args []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if start < len(s) {
		args = append(args, strings.TrimSpace(s[start:]))
	}
	return args
}

// ExtractImportsFromText 从原始文本中提取导入声明（通用启发式）。
func ExtractImportsFromText(content string, language string) []Import {
	var imports []Import
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch strings.ToLower(language) {
		case "python":
			if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "from ") {
				imports = append(imports, parsePythonImport(trimmed, lineNum+1))
			}
		case "javascript", "typescript":
			if strings.HasPrefix(trimmed, "import ") || strings.Contains(trimmed, "require(") {
				imports = append(imports, parseJSImport(trimmed, lineNum+1))
			}
		case "go":
			if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "\"") {
				imports = append(imports, parseGoImport(trimmed, lineNum+1))
			}
		}
	}
	return imports
}

func parsePythonImport(line string, lineNum int) Import {
	imp := Import{Line: lineNum}
	if strings.HasPrefix(line, "from ") {
		parts := strings.SplitN(line, " import ", 2)
		imp.Module = strings.TrimPrefix(parts[0], "from ")
		imp.Module = strings.TrimSpace(imp.Module)
		imp.IsRelative = strings.HasPrefix(imp.Module, ".")
		if len(parts) > 1 {
			items := strings.Split(parts[1], ",")
			for _, item := range items {
				item = strings.TrimSpace(item)
				if item != "" {
					imp.Items = append(imp.Items, item)
				}
			}
		}
	} else {
		mod := strings.TrimPrefix(line, "import ")
		mod = strings.TrimSpace(mod)
		if strings.Contains(mod, " as ") {
			parts := strings.SplitN(mod, " as ", 2)
			imp.Module = strings.TrimSpace(parts[0])
			imp.Alias = strings.TrimSpace(parts[1])
		} else {
			imp.Module = mod
		}
	}
	return imp
}

func parseJSImport(line string, lineNum int) Import {
	imp := Import{Line: lineNum}
	if strings.Contains(line, "require(") {
		start := strings.Index(line, "require(")
		if start >= 0 {
			rest := line[start+8:]
			end := strings.Index(rest, ")")
			if end >= 0 {
				mod := strings.TrimSpace(rest[:end])
				mod = strings.Trim(mod, `"'`)
				imp.Module = mod
			}
		}
	} else if strings.HasPrefix(line, "import ") {
		rest := strings.TrimPrefix(line, "import ")
		if strings.Contains(rest, " from ") {
			parts := strings.SplitN(rest, " from ", 2)
			imp.Module = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		}
	}
	return imp
}

func parseGoImport(line string, lineNum int) Import {
	imp := Import{Line: lineNum}
	if strings.HasPrefix(line, "import ") {
		rest := strings.TrimPrefix(line, "import ")
		rest = strings.TrimSpace(rest)
		if strings.HasPrefix(rest, "\"") {
			imp.Module = strings.Trim(rest, "\"")
		} else if strings.HasPrefix(rest, "(") {
			// 多行导入，简化处理
			imp.Module = strings.Trim(rest, "()\"")
		}
	}
	return imp
}
