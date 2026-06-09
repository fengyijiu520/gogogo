// Package ir 定义了 skill-scanner 的中间表示层 (Intermediate Representation)。
//
// IR 层是静态分析的核心基础设施，将源代码从原始文本转换为结构化表示，
// 使得分析器可以在 AST/CFG/DFG 上做深层分析，而不是依赖正则匹配文本。
//
// 设计原则：
//   - 语言无关：IR 类型不绑定特定编程语言
//   - 渐进式：先支持 AST 级别，后续扩展 CFG/DFG
//   - 可缓存：IR 可序列化，支持增量扫描复用
//   - 向后兼容：旧的正则分析器可以继续工作，新分析器基于 IR
package ir

import (
	"fmt"
	"strings"
)

// =============================================================================
// 核心类型：文件级表示
// =============================================================================

// File 表示一个已解析的源代码文件。
// 这是 IR 层的顶层容器，持有 AST、函数列表、调用关系等结构化信息。
type File struct {
	// Path 文件的相对路径
	Path string `json:"path"`
	// Language 编程语言标识 (python, javascript, typescript, go, java, shell, ...)
	Language string `json:"language"`
	// RawContent 原始源代码文本（保留用于报告展示和正则降级分析）
	RawContent string `json:"raw_content,omitempty"`
	// Functions 文件中定义的函数列表
	Functions []Function `json:"functions,omitempty"`
	// Imports 文件中的导入/引用声明
	Imports []Import `json:"imports,omitempty"`
	// TopLevelCalls 文件顶层（函数外）的调用表达式
	TopLevelCalls []CallExpr `json:"top_level_calls,omitempty"`
	// Assignments 文件顶层的赋值/变量声明
	Assignments []Assignment `json:"assignments,omitempty"`
	// StringLiterals 文件中的字符串字面量（用于凭据检测等）
	StringLiterals []StringLiteral `json:"string_literals,omitempty"`
	// ParseError 解析失败时的错误信息（降级到正则分析）
	ParseError string `json:"parse_error,omitempty"`
}

// IsParsed 返回文件是否成功解析为 AST。
func (f *File) IsParsed() bool {
	return f.ParseError == "" && len(f.Functions) > 0
}

// AllCallExprs 返回文件中所有位置的调用表达式（函数内 + 顶层）。
func (f *File) AllCallExprs() []CallExpr {
	var calls []CallExpr
	calls = append(calls, f.TopLevelCalls...)
	for _, fn := range f.Functions {
		calls = append(calls, fn.Calls...)
	}
	return calls
}

// FindFunction 按名称查找函数（支持 receiver.method 形式）。
func (f *File) FindFunction(name string) *Function {
	for i := range f.Functions {
		if f.Functions[i].Name == name || f.Functions[i].QualifiedName == name {
			return &f.Functions[i]
		}
	}
	return nil
}

// =============================================================================
// 核心类型：函数级表示
// =============================================================================

// Function 表示一个函数/方法定义。
type Function struct {
	// Name 函数的简单名称
	Name string `json:"name"`
	// QualifiedName 限定名（如 module.func, Class.method）
	QualifiedName string `json:"qualified_name,omitempty"`
	// Receiver 方法的接收者类型（Go 方法、Python self 等）
	Receiver string `json:"receiver,omitempty"`
	// StartLine 起始行号
	StartLine int `json:"start_line"`
	// EndLine 结束行号
	EndLine int `json:"end_line"`
	// Parameters 参数列表
	Parameters []Parameter `json:"parameters,omitempty"`
	// Returns 返回值类型（如果可推断）
	Returns []string `json:"returns,omitempty"`
	// Calls 函数体内的调用表达式
	Calls []CallExpr `json:"calls,omitempty"`
	// Assignments 函数体内的赋值/变量声明
	Assignments []Assignment `json:"assignments,omitempty"`
	// IsExported 是否导出（公开可见）
	IsExported bool `json:"is_exported"`
	// DocComment 文档注释
	DocComment string `json:"doc_comment,omitempty"`
}

// Parameter 表示函数参数。
type Parameter struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`     // 类型注解（如果有）
	Default  string `json:"default,omitempty"`  // 默认值（如果有）
	IsVariadic bool `json:"is_variadic,omitempty"` // 是否可变参数
}

// =============================================================================
// 核心类型：调用表达式
// =============================================================================

// CallExpr 表示一个函数/方法调用。
// 这是安全分析的核心关注点 — 大多数风险都源于危险调用。
type CallExpr struct {
	// FuncName 被调用函数的名称（如 os.system, requests.post, exec.Command）
	FuncName string `json:"func_name"`
	// Line 行号
	Line int `json:"line"`
	// Column 列号
	Column int `json:"column,omitempty"`
	// Args 调用参数的文本表示（简化版，用于快速匹配）
	Args []string `json:"args,omitempty"`
	// ArgExprs 参数的结构化表示（用于数据流分析）
	ArgExprs []Expr `json:"arg_exprs,omitempty"`
	// Receiver 调用接收者（如 obj.method() 中的 obj）
	Receiver string `json:"receiver,omitempty"`
	// IsDynamic 是否为动态调用（变量作为函数名，如 eval(var)）
	IsDynamic bool `json:"is_dynamic,omitempty"`
	// Context 调用所在的上下文信息（所在函数名等）
	Context string `json:"context,omitempty"`
}

// IsMethodCall 返回是否为方法调用（如 obj.method()）。
func (c *CallExpr) IsMethodCall() bool {
	return c.Receiver != ""
}

// Category 返回调用的安全类别（基于函数名的启发式分类）。
func (c *CallExpr) Category() string {
	return ClassifyCall(c.FuncName)
}

// =============================================================================
// 核心类型：表达式（用于数据流分析）
// =============================================================================

// Expr 表示一个表达式节点。
// 这是数据流分析的基础，用于追踪变量的来源和传播。
type Expr struct {
	// Kind 表达式类型
	Kind ExprKind `json:"kind"`
	// Text 表达式的文本表示
	Text string `json:"text"`
	// VarName 如果是变量引用，变量名
	VarName string `json:"var_name,omitempty"`
	// FuncCall 如果是函数调用，调用信息
	FuncCall *CallExpr `json:"func_call,omitempty"`
}

// ExprKind 表达式类型枚举。
type ExprKind string

const (
	ExprLiteral    ExprKind = "literal"     // 字面量
	ExprVariable   ExprKind = "variable"    // 变量引用
	ExprCall       ExprKind = "call"        // 函数调用
	ExprBinary     ExprKind = "binary"      // 二元运算
	ExprIndex      ExprKind = "index"       // 索引访问
	ExprSlice      ExprKind = "slice"       // 切片访问
	ExprUnknown    ExprKind = "unknown"     // 无法解析
)

// =============================================================================
// 核心类型：赋值/变量声明
// =============================================================================

// Assignment 表示一个赋值或变量声明。
// 用于追踪数据流：变量从哪里来（source），到哪里去（sink）。
type Assignment struct {
	// VarName 被赋值的变量名
	VarName string `json:"var_name"`
	// Line 行号
	Line int `json:"line"`
	// RHS 右值的文本表示
	RHS string `json:"rhs,omitempty"`
	// RHSExpr 右值的结构化表示
	RHSExpr *Expr `json:"rhs_expr,omitempty"`
	// IsTainted 是否标记为受污染（来自不可信输入）
	IsTainted bool `json:"is_tainted,omitempty"`
	// TaintSource 污染来源（如 os.Getenv, request.args）
	TaintSource string `json:"taint_source,omitempty"`
	// Context 所在函数名（顶层为空）
	Context string `json:"context,omitempty"`
}

// =============================================================================
// 核心类型：导入声明
// =============================================================================

// Import 表示一个导入/引用声明。
type Import struct {
	// Module 被导入的模块名
	Module string `json:"module"`
	// Alias 导入别名（如 import foo as bar 中的 bar）
	Alias string `json:"alias,omitempty"`
	// Items 具名导入列表（如 from foo import bar, baz 中的 [bar, baz]）
	Items []string `json:"items,omitempty"`
	// Line 行号
	Line int `json:"line"`
	// IsRelative 是否为相对导入
	IsRelative bool `json:"is_relative,omitempty"`
}

// =============================================================================
// 核心类型：字符串字面量
// =============================================================================

// StringLiteral 表示一个字符串字面量。
// 用于凭据检测、URL 提取等。
type StringLiteral struct {
	// Value 字符串内容
	Value string `json:"value"`
	// Line 行号
	Line int `json:"line"`
	// Context 所在行的代码上下文
	Context string `json:"context,omitempty"`
	// IsHighEntropy 是否为高熵字符串（可能是密钥）
	IsHighEntropy bool `json:"is_high_entropy,omitempty"`
}

// =============================================================================
// 核心类型：分析结果
// =============================================================================

// Finding 表示一个安全发现。
// 比 plugins.Finding 更丰富，包含数据流和 IR 信息。
type Finding struct {
	// RuleID 规则标识
	RuleID string `json:"rule_id"`
	// Severity 严重性：高风险 / 中风险 / 低风险
	Severity string `json:"severity"`
	// Title 标题
	Title string `json:"title"`
	// Description 描述
	Description string `json:"description"`
	// Category 安全类别
	Category string `json:"category"`
	// Location 位置（文件:行号）
	Location string `json:"location"`
	// CodeSnippet 代码片段
	CodeSnippet string `json:"code_snippet,omitempty"`
	// Source 调用表达式（触发此发现的调用）
	Source *CallExpr `json:"source,omitempty"`
	// DataFlow 数据流路径（source → transform → sink）
	DataFlow []DataFlowStep `json:"data_flow,omitempty"`
	// Confidence 置信度：高 / 中 / 低 / 待复核
	Confidence string `json:"confidence"`
}

// DataFlowStep 表示数据流路径中的一步。
type DataFlowStep struct {
	// Kind 步骤类型：source / transform / sink
	Kind string `json:"kind"`
	// VarName 涉及的变量名
	VarName string `json:"var_name"`
	// Location 位置
	Location string `json:"location"`
	// Description 描述
	Description string `json:"description"`
}

// =============================================================================
// 核心接口：分析器
// =============================================================================

// Analyzer 定义了基于 IR 的分析器接口。
// 所有新的安全分析器都应该实现此接口。
type Analyzer interface {
	// Name 返回分析器名称
	Name() string
	// Analyze 对解析后的文件进行分析，返回发现列表
	Analyze(files []File) []Finding
}

// Parser 定义了源代码解析器接口。
// 每种语言实现一个 Parser，将原始文本转换为 IR File。
type Parser interface {
	// Language 返回此解析器支持的语言标识
	Language() string
	// Extensions 返回此解析器支持的文件扩展名
	Extensions() []string
	// Parse 将源代码解析为 IR File
	Parse(path string, content string) (*File, error)
}

// =============================================================================
// 调用分类工具
// =============================================================================

// CallCategory 调用的安全类别。
type CallCategory string

const (
	CatCommandExec    CallCategory = "command_exec"     // 命令执行
	CatNetworkAccess  CallCategory = "network_access"   // 网络访问
	CatFileRead       CallCategory = "file_read"        // 文件读取
	CatFileWrite      CallCategory = "file_write"       // 文件写入
	CatCryptoOp       CallCategory = "crypto"           // 加密操作
	CatSerialize      CallCategory = "serialize"         // 序列化/反序列化
	CatEnvAccess      CallCategory = "env_access"       // 环境变量访问
	CatPrivilegeEsc   CallCategory = "privilege_escalation" // 权限提升
	CatDataCollection CallCategory = "data_collection"  // 数据收集
	CatPersistence    CallCategory = "persistence"       // 持久化
	CatUnsafe         CallCategory = "unsafe"            // 不安全操作
	CatBenign         CallCategory = "benign"            // 安全/良性
)

// callClassifiers 按优先级排列的调用分类规则。
var callClassifiers = []struct {
	pattern  string
	category CallCategory
}{
	// 命令执行
	{"os.system", CatCommandExec},
	{"subprocess", CatCommandExec},
	{"exec.Command", CatCommandExec},
	{"syscall.Exec", CatCommandExec},
	{"Runtime.exec", CatCommandExec},
	{"ProcessBuilder", CatCommandExec},
	{"child_process", CatCommandExec},
	{"shell_exec", CatCommandExec},
	{"passthru", CatCommandExec},
	{"popen", CatCommandExec},
	{"eval", CatCommandExec},
	{"exec", CatCommandExec},
	{"spawn", CatCommandExec},

	// 网络访问
	{"requests.get", CatNetworkAccess},
	{"requests.post", CatNetworkAccess},
	{"requests.put", CatNetworkAccess},
	{"requests.delete", CatNetworkAccess},
	{"httpx", CatNetworkAccess},
	{"urllib", CatNetworkAccess},
	{"fetch", CatNetworkAccess},
	{"axios", CatNetworkAccess},
	{"HttpClient", CatNetworkAccess},
	{"http.Get", CatNetworkAccess},
	{"http.Post", CatNetworkAccess},
	{"net.Dial", CatNetworkAccess},
	{"websocket", CatNetworkAccess},
	{"socket", CatNetworkAccess},
	{"curl", CatNetworkAccess},
	{"wget", CatNetworkAccess},

	// 文件读取
	{"open", CatFileRead},
	{"readFile", CatFileRead},
	{"os.ReadFile", CatFileRead},
	{"ioutil.ReadFile", CatFileRead},
	{"fs.readFileSync", CatFileRead},
	{"file_get_contents", CatFileRead},
	{"fopen", CatFileRead},

	// 文件写入
	{"writeFile", CatFileWrite},
	{"os.WriteFile", CatFileWrite},
	{"os.Create", CatFileWrite},
	{"ioutil.WriteFile", CatFileWrite},
	{"fs.writeFileSync", CatFileWrite},
	{"file_put_contents", CatFileWrite},
	{"fwrite", CatFileWrite},
	{"SaveUploadedFile", CatFileWrite},

	// 加密操作
	{"crypto", CatCryptoOp},
	{"openssl", CatCryptoOp},
	{"hashlib", CatCryptoOp},
	{"bcrypt", CatCryptoOp},
	{"encrypt", CatCryptoOp},
	{"decrypt", CatCryptoOp},

	// 序列化
	{"json.loads", CatSerialize},
	{"json.dumps", CatSerialize},
	{"pickle", CatSerialize},
	{"yaml.load", CatSerialize},
	{"marshal", CatSerialize},
	{"deserialize", CatSerialize},

	// 环境变量
	{"os.Getenv", CatEnvAccess},
	{"process.env", CatEnvAccess},
	{"os.environ", CatEnvAccess},
	{"getenv", CatEnvAccess},

	// 权限提升
	{"sudo", CatPrivilegeEsc},
	{"setuid", CatPrivilegeEsc},
	{"chmod", CatPrivilegeEsc},
	{"chown", CatPrivilegeEsc},

	// 数据收集
	{"collect", CatDataCollection},
	{"harvest", CatDataCollection},
	{"scrape", CatDataCollection},
	{"track", CatDataCollection},

	// 持久化
	{"crontab", CatPersistence},
	{"systemd", CatPersistence},
	{"autostart", CatPersistence},
	{"registry", CatPersistence},

	// 不安全操作
	{"pickle.loads", CatUnsafe},
	{"yaml.load", CatUnsafe},
	{"eval", CatUnsafe},
	{"exec", CatUnsafe},
	{"__import__", CatUnsafe},
}

// ClassifyCall 根据函数名返回安全类别。
func ClassifyCall(funcName string) string {
	lower := strings.ToLower(funcName)
	for _, c := range callClassifiers {
		if strings.Contains(lower, strings.ToLower(c.pattern)) {
			return string(c.category)
		}
	}
	return string(CatBenign)
}

// IsDangerousCall 判断调用是否为已知危险调用。
func IsDangerousCall(funcName string) bool {
	cat := CallCategory(ClassifyCall(funcName))
	switch cat {
	case CatCommandExec, CatPrivilegeEsc, CatUnsafe:
		return true
	default:
		return false
	}
}

// IsNetworkCall 判断调用是否为网络相关调用。
func IsNetworkCall(funcName string) bool {
	return CallCategory(ClassifyCall(funcName)) == CatNetworkAccess
}

// IsFileOperation 判断调用是否为文件操作。
func IsFileOperation(funcName string) bool {
	cat := CallCategory(ClassifyCall(funcName))
	return cat == CatFileRead || cat == CatFileWrite
}

// =============================================================================
// 工具函数
// =============================================================================

// Location 格式化文件位置。
func Location(path string, line int) string {
	if line > 0 {
		return fmt.Sprintf("%s:%d", path, line)
	}
	return path
}

// Locationf 带格式化的位置。
func Locationf(path string, line int, format string, args ...interface{}) string {
	loc := Location(path, line)
	if format != "" {
		return loc + " " + fmt.Sprintf(format, args...)
	}
	return loc
}
