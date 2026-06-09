package ir

import (
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/bash"
	"github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/csharp"
	"github.com/smacker/go-tree-sitter/css"
	"github.com/smacker/go-tree-sitter/cue"
	"github.com/smacker/go-tree-sitter/dockerfile"
	"github.com/smacker/go-tree-sitter/elixir"
	"github.com/smacker/go-tree-sitter/elm"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/groovy"
	"github.com/smacker/go-tree-sitter/hcl"
	"github.com/smacker/go-tree-sitter/html"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/kotlin"
	"github.com/smacker/go-tree-sitter/lua"
	markdown "github.com/smacker/go-tree-sitter/markdown/tree-sitter-markdown"
	"github.com/smacker/go-tree-sitter/ocaml"
	"github.com/smacker/go-tree-sitter/php"
	"github.com/smacker/go-tree-sitter/protobuf"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/ruby"
	"github.com/smacker/go-tree-sitter/rust"
	"github.com/smacker/go-tree-sitter/scala"
	"github.com/smacker/go-tree-sitter/sql"
	"github.com/smacker/go-tree-sitter/svelte"
	"github.com/smacker/go-tree-sitter/swift"
	"github.com/smacker/go-tree-sitter/toml"
	tsparser "github.com/smacker/go-tree-sitter/typescript/typescript"
	tsxpather "github.com/smacker/go-tree-sitter/typescript/tsx"
	"github.com/smacker/go-tree-sitter/yaml"
)

// =============================================================================
// Tree-sitter 解析器实现
// =============================================================================

// tsParser 基于 Tree-sitter 的多语言解析器。
type tsParser struct {
	lang       string
	extensions []string
	grammar    *sitter.Language
}

// newTSParser 创建 Tree-sitter 解析器。
func newTSParser(lang string, extensions []string, grammar *sitter.Language) *tsParser {
	return &tsParser{
		lang:       lang,
		extensions: extensions,
		grammar:    grammar,
	}
}

func (p *tsParser) Language() string   { return p.lang }
func (p *tsParser) Extensions() []string { return p.extensions }

func (p *tsParser) Parse(path string, content string) (*File, error) {
	parser := sitter.NewParser()
	parser.SetLanguage(p.grammar)

	tree := parser.Parse(nil, []byte(content))
	if tree == nil {
		return nil, fmt.Errorf("tree-sitter parse returned nil tree")
	}
	defer tree.Close()

	root := tree.RootNode()

	file := &File{
		Path:       path,
		Language:   p.lang,
		RawContent: content,
	}

	// 遍历 AST 提取结构化信息
	p.extractFromFile(root, content, file)

	return file, nil
}

// extractFromFile 从 AST 根节点提取文件级信息。
func (p *tsParser) extractFromFile(root *sitter.Node, content string, file *File) {
	lines := strings.Split(content, "\n")

	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		nodeType := child.Type()

		switch p.lang {
		case "python":
			p.extractPythonNode(child, lines, file)
		case "go":
			p.extractGoNode(child, lines, file)
		case "javascript", "typescript":
			p.extractJSNode(child, lines, file)
		default:
			// 通用提取：只提取调用表达式
			p.extractGenericCalls(child, lines, file)
		}
		_ = nodeType
	}
}

// =============================================================================
// Python AST 提取
// =============================================================================

func (p *tsParser) extractPythonNode(node *sitter.Node, lines []string, file *File) {
	switch node.Type() {
	case "function_definition":
		fn := p.extractPythonFunction(node, lines)
		file.Functions = append(file.Functions, fn)
	case "import_statement":
		imp := p.extractPythonImportFromNode(node, lines)
		file.Imports = append(file.Imports, imp)
	case "import_from_statement":
		imp := p.extractPythonImportFromStatement(node, lines)
		file.Imports = append(file.Imports, imp)
	case "expression_statement":
		// 检查是否为顶层调用
		if callNode := findChildByType(node, "call"); callNode != nil {
			call := p.extractCallExpr(callNode, lines, "")
			file.TopLevelCalls = append(file.TopLevelCalls, call)
		}
	case "assignment":
		assign := p.extractPythonAssignment(node, lines, "")
		if assign.VarName != "" {
			file.Assignments = append(file.Assignments, assign)
		}
	}
}

func (p *tsParser) extractPythonFunction(node *sitter.Node, lines []string) Function {
	fn := Function{
		StartLine: int(node.StartPoint().Row) + 1,
		EndLine:   int(node.EndPoint().Row) + 1,
	}

	// 提取函数名
	if nameNode := findChildByType(node, "identifier"); nameNode != nil {
		fn.Name = nodeContent(nameNode, lines)
		fn.QualifiedName = fn.Name
	}

	// 提取参数
	if paramsNode := findChildByType(node, "parameters"); paramsNode != nil {
		fn.Parameters = p.extractPythonParams(paramsNode, lines)
	}

	// 提取函数体内的调用和赋值
	if bodyNode := findChildByType(node, "block"); bodyNode != nil {
		p.extractPythonBody(bodyNode, lines, &fn)
	}

	// 提取文档注释
	if fn.StartLine > 1 {
		prevLine := strings.TrimSpace(lines[fn.StartLine-2])
		if strings.HasPrefix(prevLine, `"""`) || strings.HasPrefix(prevLine, `'''`) {
			fn.DocComment = prevLine
		}
	}

	return fn
}

func (p *tsParser) extractPythonParams(node *sitter.Node, lines []string) []Parameter {
	var params []Parameter
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case "identifier":
			params = append(params, Parameter{
				Name: nodeContent(child, lines),
			})
		case "default_parameter":
			if nameNode := findChildByType(child, "identifier"); nameNode != nil {
				params = append(params, Parameter{
					Name:    nodeContent(nameNode, lines),
					Default: "...",
				})
			}
		case "typed_parameter":
			if nameNode := findChildByType(child, "identifier"); nameNode != nil {
				params = append(params, Parameter{
					Name: nodeContent(nameNode, lines),
				})
			}
		case "list_splat_parameter":
			if nameNode := findChildByType(child, "identifier"); nameNode != nil {
				params = append(params, Parameter{
					Name:       nodeContent(nameNode, lines),
					IsVariadic: true,
				})
			}
		}
	}
	return params
}

func (p *tsParser) extractPythonBody(node *sitter.Node, lines []string, fn *Function) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case "expression_statement":
			// expression_statement 可能包含 call 或 assignment
			if callNode := findChildByType(child, "call"); callNode != nil {
				call := p.extractCallExpr(callNode, lines, fn.Name)
				fn.Calls = append(fn.Calls, call)
			}
			if assignNode := findChildByType(child, "assignment"); assignNode != nil {
				assign := p.extractPythonAssignment(assignNode, lines, fn.Name)
				if assign.VarName != "" {
					fn.Assignments = append(fn.Assignments, assign)
				}
			}
		case "assignment":
			assign := p.extractPythonAssignment(child, lines, fn.Name)
			if assign.VarName != "" {
				fn.Assignments = append(fn.Assignments, assign)
			}
		case "return_statement":
			// 检查 return 中的调用
			p.extractCallsFromNode(child, lines, fn, fn.Name)
		case "if_statement", "for_statement", "while_statement", "with_statement", "try_statement":
			// 递归进入控制流
			p.extractCallsFromNode(child, lines, fn, fn.Name)
		}
	}
}

func (p *tsParser) extractPythonAssignment(node *sitter.Node, lines []string, context string) Assignment {
	assign := Assignment{
		Line:    int(node.StartPoint().Row) + 1,
		Context: context,
	}
	// 左值
	if leftNode := node.Child(0); leftNode != nil {
		assign.VarName = nodeContent(leftNode, lines)
	}
	// 右值
	if rightNode := node.Child(int(node.ChildCount()) - 1); rightNode != nil {
		assign.RHS = nodeContent(rightNode, lines)
	}
	return assign
}

func (p *tsParser) extractPythonImportFromNode(node *sitter.Node, lines []string) Import {
	imp := Import{Line: int(node.StartPoint().Row) + 1}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "dotted_name" || child.Type() == "identifier" {
			imp.Module = nodeContent(child, lines)
			break
		}
	}
	return imp
}

func (p *tsParser) extractPythonImportFromStatement(node *sitter.Node, lines []string) Import {
	imp := Import{Line: int(node.StartPoint().Row) + 1, IsRelative: true}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case "dotted_name", "relative_import":
			imp.Module = nodeContent(child, lines)
		case "import_list":
			for j := 0; j < int(child.ChildCount()); j++ {
				item := child.Child(j)
				if item.Type() == "identifier" || item.Type() == "dotted_name" {
					imp.Items = append(imp.Items, nodeContent(item, lines))
				}
			}
		}
	}
	return imp
}

// =============================================================================
// Go AST 提取
// =============================================================================

func (p *tsParser) extractGoNode(node *sitter.Node, lines []string, file *File) {
	switch node.Type() {
	case "function_declaration", "method_declaration":
		fn := p.extractGoFunction(node, lines)
		file.Functions = append(file.Functions, fn)
	case "import_declaration":
		imp := p.extractGoImportFromNode(node, lines)
		file.Imports = append(file.Imports, imp)
	case "call_expression":
		call := p.extractCallExpr(node, lines, "")
		file.TopLevelCalls = append(file.TopLevelCalls, call)
	case "short_var_declaration", "var_declaration":
		assign := p.extractGoAssignment(node, lines, "")
		if assign.VarName != "" {
			file.Assignments = append(file.Assignments, assign)
		}
	}
}

func (p *tsParser) extractGoFunction(node *sitter.Node, lines []string) Function {
	fn := Function{
		StartLine: int(node.StartPoint().Row) + 1,
		EndLine:   int(node.EndPoint().Row) + 1,
		IsExported: true, // Go 默认导出大写开头的函数
	}

	// 提取函数名
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "identifier" {
			name := nodeContent(child, lines)
			fn.Name = name
			fn.QualifiedName = name
			fn.IsExported = len(name) > 0 && name[0] >= 'A' && name[0] <= 'Z'
			break
		}
	}

	// 提取参数
	if paramsNode := findChildByType(node, "parameter_list"); paramsNode != nil {
		fn.Parameters = p.extractGoParams(paramsNode, lines)
	}

	// 提取函数体
	if bodyNode := findChildByType(node, "block"); bodyNode != nil {
		p.extractGoBody(bodyNode, lines, &fn)
	}

	return fn
}

func (p *tsParser) extractGoParams(node *sitter.Node, lines []string) []Parameter {
	var params []Parameter
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "parameter_declaration" {
			if nameNode := findChildByType(child, "identifier"); nameNode != nil {
				params = append(params, Parameter{
					Name: nodeContent(nameNode, lines),
				})
			}
		}
	}
	return params
}

func (p *tsParser) extractGoBody(node *sitter.Node, lines []string, fn *Function) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		p.extractGoStmt(child, lines, fn)
	}
}

func (p *tsParser) extractGoStmt(node *sitter.Node, lines []string, fn *Function) {
	switch node.Type() {
	case "call_expression":
		call := p.extractCallExpr(node, lines, fn.Name)
		fn.Calls = append(fn.Calls, call)
		// 递归检查参数中的调用
		p.extractCallsFromArgs(node, lines, fn)
	case "short_var_declaration":
		assign := p.extractGoAssignment(node, lines, fn.Name)
		if assign.VarName != "" {
			fn.Assignments = append(fn.Assignments, assign)
		}
		// 递归检查右值中的调用
		for i := 0; i < int(node.ChildCount()); i++ {
			p.extractGoStmt(node.Child(i), lines, fn)
		}
	case "expression_statement":
		for i := 0; i < int(node.ChildCount()); i++ {
			p.extractGoStmt(node.Child(i), lines, fn)
		}
	case "assignment_statement":
		assign := p.extractGoAssignment(node, lines, fn.Name)
		if assign.VarName != "" {
			fn.Assignments = append(fn.Assignments, assign)
		}
		for i := 0; i < int(node.ChildCount()); i++ {
			p.extractGoStmt(node.Child(i), lines, fn)
		}
	default:
		// 递归进入子节点
		for i := 0; i < int(node.ChildCount()); i++ {
			p.extractGoStmt(node.Child(i), lines, fn)
		}
	}
}

// extractCallsFromArgs 递归提取调用参数中的嵌套调用。
func (p *tsParser) extractCallsFromArgs(node *sitter.Node, lines []string, fn *Function) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "argument_list" {
			for j := 0; j < int(child.ChildCount()); j++ {
				arg := child.Child(j)
				if arg.Type() == "call_expression" {
					call := p.extractCallExpr(arg, lines, fn.Name)
					fn.Calls = append(fn.Calls, call)
				}
				// 递归检查更深层的嵌套调用
				p.extractCallsFromNode(arg, lines, fn, fn.Name)
			}
		}
	}
}

func (p *tsParser) extractGoAssignment(node *sitter.Node, lines []string, context string) Assignment {
	assign := Assignment{
		Line:    int(node.StartPoint().Row) + 1,
		Context: context,
	}
	// 左值
	if leftNode := node.Child(0); leftNode != nil {
		if leftNode.Type() == "expression_list" {
			if ident := leftNode.Child(0); ident != nil {
				assign.VarName = nodeContent(ident, lines)
			}
		} else {
			assign.VarName = nodeContent(leftNode, lines)
		}
	}
	// 右值
	if rightNode := node.Child(int(node.ChildCount()) - 1); rightNode != nil {
		assign.RHS = nodeContent(rightNode, lines)
	}
	return assign
}

func (p *tsParser) extractGoImportFromNode(node *sitter.Node, lines []string) Import {
	imp := Import{Line: int(node.StartPoint().Row) + 1}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "import_spec_list" {
			for j := 0; j < int(child.ChildCount()); j++ {
				spec := child.Child(j)
				if spec.Type() == "import_spec" {
					if pathNode := findChildByType(spec, "interpreted_string_literal"); pathNode != nil {
						imp.Module = strings.Trim(nodeContent(pathNode, lines), `"`)
					}
				}
			}
		} else if child.Type() == "import_spec" {
			if pathNode := findChildByType(child, "interpreted_string_literal"); pathNode != nil {
				imp.Module = strings.Trim(nodeContent(pathNode, lines), `"`)
			}
		}
	}
	return imp
}

// =============================================================================
// JavaScript/TypeScript AST 提取
// =============================================================================

func (p *tsParser) extractJSNode(node *sitter.Node, lines []string, file *File) {
	switch node.Type() {
	case "function_declaration", "arrow_function", "function":
		fn := p.extractJSFunction(node, lines)
		file.Functions = append(file.Functions, fn)
	case "import_statement":
		imp := p.extractJSImportFromNode(node, lines)
		file.Imports = append(file.Imports, imp)
	case "variable_declaration":
		p.extractJSVarDecl(node, lines, file, "")
	case "expression_statement":
		if callNode := findChildByType(node, "call_expression"); callNode != nil {
			call := p.extractCallExpr(callNode, lines, "")
			file.TopLevelCalls = append(file.TopLevelCalls, call)
		}
	}
}

func (p *tsParser) extractJSFunction(node *sitter.Node, lines []string) Function {
	fn := Function{
		StartLine:  int(node.StartPoint().Row) + 1,
		EndLine:    int(node.EndPoint().Row) + 1,
		IsExported: true,
	}

	// 提取函数名
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "identifier" {
			name := nodeContent(child, lines)
			fn.Name = name
			fn.QualifiedName = name
			break
		}
	}

	// 提取参数
	if paramsNode := findChildByType(node, "formal_parameters"); paramsNode != nil {
		fn.Parameters = p.extractJSParams(paramsNode, lines)
	}

	// 提取函数体
	if bodyNode := findChildByType(node, "statement_block"); bodyNode != nil {
		p.extractJSBody(bodyNode, lines, &fn)
	}

	return fn
}

func (p *tsParser) extractJSParams(node *sitter.Node, lines []string) []Parameter {
	var params []Parameter
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "identifier" {
			params = append(params, Parameter{
				Name: nodeContent(child, lines),
			})
		}
	}
	return params
}

func (p *tsParser) extractJSBody(node *sitter.Node, lines []string, fn *Function) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		p.extractJSStmt(child, lines, fn)
	}
}

func (p *tsParser) extractJSStmt(node *sitter.Node, lines []string, fn *Function) {
	switch node.Type() {
	case "expression_statement":
		if callNode := findChildByType(node, "call_expression"); callNode != nil {
			call := p.extractCallExpr(callNode, lines, fn.Name)
			fn.Calls = append(fn.Calls, call)
		}
	case "variable_declaration":
		p.extractJSVarDecl(node, lines, nil, fn.Name)
	case "return_statement":
		p.extractCallsFromNode(node, lines, fn, fn.Name)
	default:
		for i := 0; i < int(node.ChildCount()); i++ {
			p.extractJSStmt(node.Child(i), lines, fn)
		}
	}
}

func (p *tsParser) extractJSVarDecl(node *sitter.Node, lines []string, file *File, context string) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "variable_declarator" {
			assign := Assignment{
				Line:    int(child.StartPoint().Row) + 1,
				Context: context,
			}
			if nameNode := findChildByType(child, "identifier"); nameNode != nil {
				assign.VarName = nodeContent(nameNode, lines)
			}
			if valueNode := child.Child(int(child.ChildCount()) - 1); valueNode != nil {
				assign.RHS = nodeContent(valueNode, lines)
			}
			if file != nil && assign.VarName != "" {
				file.Assignments = append(file.Assignments, assign)
			}
		}
	}
}

func (p *tsParser) extractJSImportFromNode(node *sitter.Node, lines []string) Import {
	imp := Import{Line: int(node.StartPoint().Row) + 1}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "string" {
			imp.Module = strings.Trim(nodeContent(child, lines), `"'`)
		}
	}
	return imp
}

// =============================================================================
// 通用/降级提取
// =============================================================================

func (p *tsParser) extractGenericCalls(node *sitter.Node, lines []string, file *File) {
	if node.Type() == "call" || node.Type() == "call_expression" {
		call := p.extractCallExpr(node, lines, "")
		file.TopLevelCalls = append(file.TopLevelCalls, call)
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.extractGenericCalls(node.Child(i), lines, file)
	}
}

// =============================================================================
// 通用调用表达式提取
// =============================================================================

func (p *tsParser) extractCallExpr(node *sitter.Node, lines []string, context string) CallExpr {
	call := CallExpr{
		Line:    int(node.StartPoint().Row) + 1,
		Column:  int(node.StartPoint().Column) + 1,
		Context: context,
	}

	// 提取函数名
	if funcNode := node.Child(0); funcNode != nil {
		call.FuncName = p.resolveFuncName(funcNode, lines)
		if funcNode.Type() == "member_access_expression" || funcNode.Type() == "selector_expression" || funcNode.Type() == "attribute" {
			call.Receiver = p.resolveReceiver(funcNode, lines)
		}
	}

	// 提取参数
	if argsNode := findChildByType(node, "argument_list"); argsNode != nil {
		call.Args = p.extractArgTexts(argsNode, lines)
	}

	return call
}

func (p *tsParser) resolveFuncName(node *sitter.Node, lines []string) string {
	switch node.Type() {
	case "identifier", "field_identifier":
		return nodeContent(node, lines)
	case "member_access_expression", "selector_expression", "attribute":
		// obj.method 形式
		parts := []string{}
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() != "." {
				parts = append(parts, nodeContent(child, lines))
			}
		}
		return strings.Join(parts, ".")
	default:
		return nodeContent(node, lines)
	}
}

func (p *tsParser) resolveReceiver(node *sitter.Node, lines []string) string {
	if node.ChildCount() > 0 {
		return nodeContent(node.Child(0), lines)
	}
	return ""
}

func (p *tsParser) extractArgTexts(node *sitter.Node, lines []string) []string {
	var args []string
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != "," && child.Type() != "(" && child.Type() != ")" {
			args = append(args, nodeContent(child, lines))
		}
	}
	return args
}

// extractCallsFromNode 递归提取节点内的调用表达式。
func (p *tsParser) extractCallsFromNode(node *sitter.Node, lines []string, fn *Function, context string) {
	if node.Type() == "call" || node.Type() == "call_expression" {
		call := p.extractCallExpr(node, lines, context)
		fn.Calls = append(fn.Calls, call)
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.extractCallsFromNode(node.Child(i), lines, fn, context)
	}
}

// =============================================================================
// 工具函数
// =============================================================================

// nodeContent 获取节点对应的源代码文本。
func nodeContent(node *sitter.Node, lines []string) string {
	startRow := int(node.StartPoint().Row)
	startCol := int(node.StartPoint().Column)
	endRow := int(node.EndPoint().Row)
	endCol := int(node.EndPoint().Column)

	if startRow == endRow {
		if startRow < len(lines) {
			line := lines[startRow]
			if startCol < len(line) && endCol <= len(line) {
				return line[startCol:endCol]
			}
		}
		return ""
	}

	// 多行
	var parts []string
	for row := startRow; row <= endRow && row < len(lines); row++ {
		line := lines[row]
		if row == startRow {
			if startCol < len(line) {
				parts = append(parts, line[startCol:])
			}
		} else if row == endRow {
			if endCol <= len(line) {
				parts = append(parts, line[:endCol])
			}
		} else {
			parts = append(parts, line)
		}
	}
	return strings.Join(parts, "\n")
}

// findChildByType 查找第一个指定类型的子节点。
func findChildByType(node *sitter.Node, nodeType string) *sitter.Node {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == nodeType {
			return child
		}
		// 递归查找
		if found := findChildByType(child, nodeType); found != nil {
			return found
		}
	}
	return nil
}

// =============================================================================
// 初始化注册
// =============================================================================

func init() {
	// ===== 脚本语言 =====
	RegisterParser(newTSParser("python", []string{".py"}, python.GetLanguage()))
	RegisterParser(newTSParser("ruby", []string{".rb", ".rake", ".gemspec"}, ruby.GetLanguage()))
	RegisterParser(newTSParser("php", []string{".php", ".phtml"}, php.GetLanguage()))
	RegisterParser(newTSParser("lua", []string{".lua"}, lua.GetLanguage()))
	RegisterParser(newTSParser("elixir", []string{".ex", ".exs"}, elixir.GetLanguage()))

	// ===== JavaScript / TypeScript =====
	RegisterParser(newTSParser("javascript", []string{".js", ".jsx", ".mjs", ".cjs"}, javascript.GetLanguage()))
	RegisterParser(newTSParser("typescript", []string{".ts"}, tsparser.GetLanguage()))
	RegisterParser(newTSParser("tsx", []string{".tsx"}, tsxpather.GetLanguage()))

	// ===== 编译型语言 =====
	RegisterParser(newTSParser("go", []string{".go"}, golang.GetLanguage()))
	RegisterParser(newTSParser("java", []string{".java"}, java.GetLanguage()))
	RegisterParser(newTSParser("c", []string{".c", ".h"}, c.GetLanguage()))
	RegisterParser(newTSParser("cpp", []string{".cpp", ".cc", ".cxx", ".hpp", ".hxx"}, cpp.GetLanguage()))
	RegisterParser(newTSParser("csharp", []string{".cs"}, csharp.GetLanguage()))
	RegisterParser(newTSParser("rust", []string{".rs"}, rust.GetLanguage()))
	RegisterParser(newTSParser("swift", []string{".swift"}, swift.GetLanguage()))
	RegisterParser(newTSParser("kotlin", []string{".kt", ".kts"}, kotlin.GetLanguage()))
	RegisterParser(newTSParser("scala", []string{".scala", ".sc"}, scala.GetLanguage()))
	RegisterParser(newTSParser("ocaml", []string{".ml", ".mli"}, ocaml.GetLanguage()))

	// ===== Shell =====
	RegisterParser(newTSParser("bash", []string{".sh", ".bash", ".zsh"}, bash.GetLanguage()))

	// ===== Web =====
	RegisterParser(newTSParser("html", []string{".html", ".htm"}, html.GetLanguage()))
	RegisterParser(newTSParser("css", []string{".css", ".scss", ".less"}, css.GetLanguage()))

	// ===== 数据/配置 =====
	RegisterParser(newTSParser("json", []string{".json"}, javascript.GetLanguage())) // JSON 是 JS 子集
	RegisterParser(newTSParser("yaml", []string{".yaml", ".yml"}, yaml.GetLanguage()))
	RegisterParser(newTSParser("toml", []string{".toml"}, toml.GetLanguage()))
	RegisterParser(newTSParser("sql", []string{".sql"}, sql.GetLanguage()))

	// ===== 基础设施 =====
	RegisterParser(newTSParser("dockerfile", []string{"Dockerfile", ".dockerfile"}, dockerfile.GetLanguage()))
	RegisterParser(newTSParser("groovy", []string{".groovy", ".gradle"}, groovy.GetLanguage()))

	// ===== 补充语言 =====
	RegisterParser(newTSParser("cue", []string{".cue"}, cue.GetLanguage()))
	RegisterParser(newTSParser("elm", []string{".elm"}, elm.GetLanguage()))
	RegisterParser(newTSParser("hcl", []string{".hcl", ".tf", ".tfvars"}, hcl.GetLanguage()))
	RegisterParser(newTSParser("markdown", []string{".md", ".markdown"}, markdown.GetLanguage()))
	RegisterParser(newTSParser("protobuf", []string{".proto"}, protobuf.GetLanguage()))
	RegisterParser(newTSParser("svelte", []string{".svelte"}, svelte.GetLanguage()))
}
