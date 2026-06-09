package ir

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// =============================================================================
// 代码相似性检索 (Similarity Search)
//
// 将已知漏洞模式向量化，新代码与之比较，发现相似的潜在风险。
// 这是对正则匹配和污点分析的补充 — 能发现"模式相似但关键字不同"的风险。
//
// 工作流：
//   1. 预定义漏洞模式库（KnownVulnPattern）
//   2. 新代码的函数/代码片段与模式库比较相似度
//   3. 超过阈值的匹配报告为发现
//
// 与 embedder.Embedder 的关系：
//   - 如果有 embedder，用向量余弦相似度（精确）
//   - 如果没有 embedder，用 TF-IDF + 余弦相似度（轻量降级）
// =============================================================================

// KnownVulnPattern 已知漏洞模式。
type KnownVulnPattern struct {
	// ID 模式标识
	ID string `json:"id"`
	// Name 模式名称
	Name string `json:"name"`
	// Category 安全类别
	Category string `json:"category"`
	// Severity 严重性
	Severity string `json:"severity"`
	// Description 描述
	Description string `json:"description"`
	// CodePattern 典型代码模式（用于 TF-IDF 匹配）
	CodePattern string `json:"code_pattern"`
	// Tokens 预分词的模式特征（用于轻量匹配）
	Tokens []string `json:"tokens,omitempty"`
	// Embedding 预计算的向量（如果有 embedder）
	Embedding []float64 `json:"embedding,omitempty"`
	// Remediation 修复建议
	Remediation string `json:"remediation,omitempty"`
}

// SimilarityMatch 相似性匹配结果。
type SimilarityMatch struct {
	// PatternID 匹配的模式 ID
	PatternID string `json:"pattern_id"`
	// PatternName 模式名称
	PatternName string `json:"pattern_name"`
	// Category 安全类别
	Category string `json:"category"`
	// Severity 严重性
	Severity string `json:"severity"`
	// Similarity 相似度（0-1）
	Similarity float64 `json:"similarity"`
	// MatchedCode 被匹配的代码片段
	MatchedCode string `json:"matched_code"`
	// Location 位置
	Location string `json:"location"`
	// Remediation 修复建议
	Remediation string `json:"remediation"`
}

// SimilarityEngine 相似性检索引擎。
type SimilarityEngine struct {
	patterns []KnownVulnPattern
	embedder CodeEmbedder
	threshold float64
}

// CodeEmbedder 代码向量化接口（适配 embedder.Embedder）。
type CodeEmbedder interface {
	Embed(text string) ([]float64, error)
	BatchEmbed(texts []string) ([][]float64, error)
}

// NewSimilarityEngine 创建相似性检索引擎。
func NewSimilarityEngine(patterns []KnownVulnPattern, embedder CodeEmbedder, threshold float64) *SimilarityEngine {
	if len(patterns) == 0 {
		patterns = DefaultVulnPatterns()
	}
	if threshold <= 0 || threshold > 1 {
		threshold = 0.7
	}
	e := &SimilarityEngine{
		patterns:  patterns,
		embedder:  embedder,
		threshold: threshold,
	}
	// 预计算模式的 token（如果没有 embedder）
	if embedder == nil {
		for i := range patterns {
			if len(patterns[i].Tokens) == 0 {
				patterns[i].Tokens = Tokenize(patterns[i].CodePattern)
			}
		}
	}
	return e
}

// Search 在文件中搜索与已知漏洞模式相似的代码。
func (e *SimilarityEngine) Search(files []File) []SimilarityMatch {
	var matches []SimilarityMatch

	for _, file := range files {
		// 搜索函数
		for _, fn := range file.Functions {
			code := extractFunctionCode(file, fn)
			m := e.matchCode(code, file.Path, fn.StartLine)
			matches = append(matches, m...)
		}
		// 搜索顶层调用
		for _, call := range file.TopLevelCalls {
			code := call.FuncName + "(" + strings.Join(call.Args, ", ") + ")"
			m := e.matchCode(code, file.Path, call.Line)
			matches = append(matches, m...)
		}
	}

	// 按相似度排序
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Similarity > matches[j].Similarity
	})

	return matches
}

// matchCode 将代码片段与所有模式比较。
func (e *SimilarityEngine) matchCode(code, filePath string, line int) []SimilarityMatch {
	if strings.TrimSpace(code) == "" {
		return nil
	}

	var matches []SimilarityMatch
	codeTokens := Tokenize(code)

	for _, pattern := range e.patterns {
		sim := e.computeSimilarity(code, codeTokens, pattern)
		if sim >= e.threshold {
			matches = append(matches, SimilarityMatch{
				PatternID:   pattern.ID,
				PatternName: pattern.Name,
				Category:    pattern.Category,
				Severity:    pattern.Severity,
				Similarity:  sim,
				MatchedCode: truncate(code, 200),
				Location:    Location(filePath, line),
				Remediation: pattern.Remediation,
			})
		}
	}

	return matches
}

// computeSimilarity 计算代码与模式的相似度。
func (e *SimilarityEngine) computeSimilarity(code string, codeTokens []string, pattern KnownVulnPattern) float64 {
	if e.embedder != nil && len(pattern.Embedding) > 0 {
		// 向量模式：用 embedder 计算代码向量
		codeVec, err := e.embedder.Embed(code)
		if err != nil || len(codeVec) == 0 {
			return e.tokenSimilarity(codeTokens, pattern.Tokens)
		}
		return CosineSimilarity(codeVec, pattern.Embedding)
	}

	// 降级模式：token 相似度
	return e.tokenSimilarity(codeTokens, pattern.Tokens)
}

// tokenSimilarity 基于 token 的余弦相似度（TF-IDF 近似 + 安全关键词加权）。
func (e *SimilarityEngine) tokenSimilarity(tokensA, tokensB []string) float64 {
	if len(tokensA) == 0 || len(tokensB) == 0 {
		return 0
	}

	// 构建词频向量（安全关键词加权）
	freqA := tokenFreqWeighted(tokensA)
	freqB := tokenFreqWeighted(tokensB)

	// 合并所有 token
	allTokens := make(map[string]bool)
	for t := range freqA {
		allTokens[t] = true
	}
	for t := range freqB {
		allTokens[t] = true
	}

	// 计算余弦相似度
	var dotProduct, normA, normB float64
	for t := range allTokens {
		a := freqA[t]
		b := freqB[t]
		dotProduct += a * b
		normA += a * a
		normB += b * b
	}

	if normA == 0 || normB == 0 {
		return 0
	}
	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}

// securityTokenWeight 安全关键词权重。
// 安全相关的 token 权重更高，提升匹配精度。
var securityTokenWeight = map[string]float64{
	// 命令执行
	"os.system": 3.0, "subprocess": 3.0, "exec": 3.0, "eval": 3.0,
	"popen": 3.0, "shell_exec": 3.0, "execve": 3.0, "spawn": 2.5,
	// 网络
	"requests.post": 3.0, "requests.get": 2.5, "http.post": 3.0,
	"fetch": 2.0, "axios": 2.5, "urllib": 2.0, "socket": 2.0,
	"websocket": 2.0, "dns": 2.0,
	// 凭据
	"getenv": 2.5, "environ": 2.5, "secret": 3.0, "token": 2.5,
	"credential": 3.0, "password": 3.0, "api_key": 3.0, "private_key": 3.0,
	// 文件
	"readFile": 2.0, "writeFile": 2.0, "open": 1.5,
	// 危险操作
	"pickle": 3.0, "yaml.load": 3.0, "marshal": 3.0,
	"crontab": 3.0, "autostart": 3.0, "setuid": 3.0,
	"ptrace": 3.0, "mmap": 2.5, "ctypes": 3.0,
	// 数据收集
	"screenshot": 3.0, "keylog": 3.0, "clipboard": 2.5,
	"cookie": 2.5, "wallet": 3.0, "mnemonic": 3.0,
	// 反检测
	"sandbox": 2.5, "debugger": 2.5, "vmware": 2.5, "vbox": 2.5,
}

// tokenFreqWeighted 计算加权 token 频率。
func tokenFreqWeighted(tokens []string) map[string]float64 {
	freq := make(map[string]float64)
	for _, t := range tokens {
		weight := 1.0
		if w, ok := securityTokenWeight[t]; ok {
			weight = w
		}
		freq[t] += weight
	}
	return freq
}

// =============================================================================
// Token 化
// =============================================================================

// Tokenize 将代码分词为特征 token。
func Tokenize(code string) []string {
	code = strings.ToLower(code)

	// 分割符
	replacer := strings.NewReplacer(
		"(", " ", ")", " ", "[", " ", "]", " ", "{", " ", "}", " ",
		",", " ", ".", " ", ":", " ", ";", " ", "=", " ", "+", " ",
		"-", " ", "*", " ", "/", " ", "&", " ", "|", " ", "!", " ",
		"<", " ", ">", " ", "~", " ", "^", " ", "%", " ", "@", " ",
		"#", " ", "\n", " ", "\t", " ", "\r", " ",
	)
	code = replacer.Replace(code)

	parts := strings.Fields(code)

	// 过滤停用词和过短的 token
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "is": true, "are": true,
		"was": true, "were": true, "be": true, "been": true, "being": true,
		"have": true, "has": true, "had": true, "do": true, "does": true,
		"did": true, "will": true, "would": true, "could": true, "should": true,
		"may": true, "might": true, "shall": true, "can": true, "to": true,
		"of": true, "in": true, "for": true, "on": true, "with": true,
		"at": true, "by": true, "from": true, "as": true, "into": true,
		"def": true, "return": true, "if": true, "else": true, "elif": true,
		"while": true, "import": true, "class": true,
		"true": true, "false": true, "none": true, "null": true, "nil": true,
		"var": true, "func": true, "package": true, "const": true, "type": true,
	}

	var tokens []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if len(p) < 2 || stopWords[p] {
			continue
		}
		tokens = append(tokens, p)
	}

	return tokens
}

// tokenFreq 计算 token 频率。
func tokenFreq(tokens []string) map[string]int {
	freq := make(map[string]int)
	for _, t := range tokens {
		freq[t]++
	}
	return freq
}

// =============================================================================
// 预定义漏洞模式库
// =============================================================================

// DefaultVulnPatterns 返回预定义的漏洞模式。
func DefaultVulnPatterns() []KnownVulnPattern {
	return []KnownVulnPattern{
		// 命令注入
		{
			ID:          "vuln-cmd-injection",
			Name:        "命令注入模式",
			Category:    "command_exec",
			Severity:    "高风险",
			Description: "用户输入直接拼接到命令执行函数，存在命令注入风险",
			CodePattern: "os.system subprocess.call exec.Command shell_exec popen",
			Remediation: "使用参数化命令执行，禁止字符串拼接",
		},
		{
			ID:          "vuln-eval-exec",
			Name:        "动态代码执行",
			Category:    "command_exec",
			Severity:    "高风险",
			Description: "使用 eval/exec 执行动态代码，存在代码注入风险",
			CodePattern: "eval exec compile __import__",
			Remediation: "避免使用 eval/exec，改用安全的替代方案",
		},

		// 数据泄露
		{
			ID:          "vuln-credential-exfil",
			Name:        "凭据外发模式",
			Category:    "network_access",
			Severity:    "高风险",
			Description: "读取凭据/密钥后通过网络外发",
			CodePattern: "getenv environ secret key token credential requests.post http.post fetch axios",
			Remediation: "禁止将凭据通过网络传输，使用安全的密钥管理",
		},
		{
			ID:          "vuln-data-exfil",
			Name:        "数据外发模式",
			Category:    "network_access",
			Severity:    "高风险",
			Description: "读取文件或数据后通过网络外发",
			CodePattern: "readFile open read requests.post http.post fetch upload send",
			Remediation: "限制网络外发内容，增加数据脱敏策略",
		},
		{
			ID:          "vuln-dns-exfil",
			Name:        "DNS 隧道外发",
			Category:    "network_access",
			Severity:    "高风险",
			Description: "通过 DNS 查询外发数据",
			CodePattern: "dns resolve query nslookup dig socket getaddrinfo",
			Remediation: "监控 DNS 查询异常，限制 DNS 查询频率",
		},

		// 文件操作
		{
			ID:          "vuln-path-traversal",
			Name:        "路径遍历模式",
			Category:    "file_read",
			Severity:    "高风险",
			Description: "文件路径包含用户输入，存在路径遍历风险",
			CodePattern: "open readFile read __file__ path join dirname .. traversal",
			Remediation: "对文件路径做白名单校验，禁止 .. 遍历",
		},
		{
			ID:          "vuln-arbitrary-write",
			Name:        "任意文件写入",
			Category:    "file_write",
			Severity:    "高风险",
			Description: "写入路径由外部控制，存在任意文件写入风险",
			CodePattern: "writeFile write open save create mkdir chmod",
			Remediation: "限制写入目录白名单，校验文件名",
		},

		// 反序列化
		{
			ID:          "vuln-unsafe-deserialize",
			Name:        "不安全反序列化",
			Category:    "unsafe",
			Severity:    "高风险",
			Description: "反序列化不可信数据，存在远程代码执行风险",
			CodePattern: "pickle.loads yaml.load marshal.loads json.loads eval exec",
			Remediation: "使用安全的反序列化库，对输入做校验",
		},

		// 持久化
		{
			ID:          "vuln-crontab-persist",
			Name:        "定时任务持久化",
			Category:    "persistence",
			Severity:    "高风险",
			Description: "创建定时任务实现持久化",
			CodePattern: "crontab cron schedule timer setInterval setTimeout systemd",
			Remediation: "禁止自动创建定时任务，需要人工审批",
		},
		{
			ID:          "vuln-autostart",
			Name:        "自启动持久化",
			Category:    "persistence",
			Severity:    "高风险",
			Description: "写入自启动配置实现持久化",
			CodePattern: "autostart rc.local profile bashrc systemd launchd registry",
			Remediation: "禁止修改自启动配置",
		},

		// 加密挖矿
		{
			ID:          "vuln-crypto-mining",
			Name:        "加密挖矿模式",
			Category:    "command_exec",
			Severity:    "高风险",
			Description: "代码包含加密挖矿特征",
			CodePattern: "mining miner xmrig stratum pool hash rate crypto coin bitcoin ethereum",
			Remediation: "禁止加密挖矿行为",
		},

		// 数据窃取
		{
			ID:          "vuln-browser-data",
			Name:        "浏览器数据窃取",
			Category:    "data_collection",
			Severity:    "高风险",
			Description: "读取浏览器 cookie/密码/历史记录",
			CodePattern: "cookie password history chrome firefox browser sqlite login data",
			Remediation: "禁止读取浏览器数据",
		},
		{
			ID:          "vuln-ssh-key-steal",
			Name:        "SSH 密钥窃取",
			Category:    "data_collection",
			Severity:    "高风险",
			Description: "读取 SSH 私钥文件",
			CodePattern: "ssh id_rsa id_ed25519 authorized_keys private key openssh",
			Remediation: "禁止读取 SSH 密钥",
		},

		// 隐蔽通道
		{
			ID:          "vuln-steganography",
			Name:        "隐写术",
			Category:    "network_access",
			Severity:    "中风险",
			Description: "使用隐写术隐藏数据传输",
			CodePattern: "steganography image pixel encode decode embed extract png jpg",
			Remediation: "监控图片处理异常",
		},

		// 环境检测
		{
			ID:          "vuln-anti-debug",
			Name:        "反调试/反沙箱",
			Category:    "unsafe",
			Severity:    "中风险",
			Description: "检测调试器或沙箱环境，可能用于逃避分析",
			CodePattern: "debugger ptrace isatty sys.platform vmware vbox sandbox detection anti",
			Remediation: "标记为可疑行为，需要人工复核",
		},

		// ===== 扩展模式：覆盖更多攻击向量 =====

		// SSRF
		{
			ID:          "vuln-ssrf",
			Name:        "服务端请求伪造",
			Category:    "network_access",
			Severity:    "高风险",
			Description: "URL 由用户输入控制，存在 SSRF 风险",
			CodePattern: "requests.get requests.post urllib http.client fetch axios url input param redirect",
			Remediation: "URL 白名单校验，禁止用户控制请求目标",
		},

		// SQL 注入
		{
			ID:          "vuln-sql-injection",
			Name:        "SQL 注入模式",
			Category:    "command_exec",
			Severity:    "高风险",
			Description: "SQL 查询拼接用户输入，存在 SQL 注入风险",
			CodePattern: "execute cursor query select insert update delete where concat format string sql",
			Remediation: "使用参数化查询，禁止字符串拼接 SQL",
		},

		// XXE
		{
			ID:          "vuln-xxe",
			Name:        "XML 外部实体注入",
			Category:    "command_exec",
			Severity:    "高风险",
			Description: "解析 XML 时未禁用外部实体，存在 XXE 风险",
			CodePattern: "xml parse etree lxml sax dom external entity SYSTEM DOCTYPE",
			Remediation: "禁用外部实体解析，使用安全的 XML 解析器",
		},

		// 日志注入
		{
			ID:          "vuln-log-injection",
			Name:        "日志注入模式",
			Category:    "unsafe",
			Severity:    "中风险",
			Description: "用户输入直接写入日志，可能伪造日志或注入恶意内容",
			CodePattern: "logging log logger info warn error debug print format input user",
			Remediation: "对日志内容做转义和校验",
		},

		// 正则 DoS
		{
			ID:          "vuln-redos",
			Name:        "正则表达式 DoS",
			Category:    "unsafe",
			Severity:    "中风险",
			Description: "使用复杂正则表达式匹配用户输入，可能导致 ReDoS",
			CodePattern: "re.match re.search re.compile regex regexp pattern input user",
			Remediation: "限制正则复杂度，设置匹配超时",
		},

		// WebSocket 劫持
		{
			ID:          "vuln-websocket-hijack",
			Name:        "WebSocket 劫持",
			Category:    "network_access",
			Severity:    "中风险",
			Description: "WebSocket 连接未校验来源，可能被劫持",
			CodePattern: "websocket ws wss socket connect upgrade origin header",
			Remediation: "校验 WebSocket Origin 头，限制连接来源",
		},

		// 供应链攻击
		{
			ID:          "vuln-supply-chain",
			Name:        "供应链攻击模式",
			Category:    "unsafe",
			Severity:    "高风险",
			Description: "安装依赖时执行自定义脚本，存在供应链攻击风险",
			CodePattern: "npm install pip install postinstall preinstall scripts setup.py install_requires",
			Remediation: "锁定依赖版本，禁用安装脚本",
		},

		// 后门模式
		{
			ID:          "vuln-backdoor",
			Name:        "后门模式",
			Category:    "command_exec",
			Severity:    "高风险",
			Description: "代码包含反向 shell 或后门特征",
			CodePattern: "reverse shell bash -i nc netcat /dev/tcp connect socket exec /bin/sh cmd.exe powershell",
			Remediation: "禁止反向 shell 和后门代码",
		},

		// 键盘记录
		{
			ID:          "vuln-keylogger",
			Name:        "键盘记录模式",
			Category:    "data_collection",
			Severity:    "高风险",
			Description: "监听键盘输入，存在键盘记录风险",
			CodePattern: "keyboard keypress keylog pynput xinput evdev input hook listener",
			Remediation: "禁止键盘监听行为",
		},

		// 屏幕截图
		{
			ID:          "vuln-screenshot",
			Name:        "屏幕截图模式",
			Category:    "data_collection",
			Severity:    "高风险",
			Description: "截取屏幕内容，可能泄露敏感信息",
			CodePattern: "screenshot screencapture PIL ImageGrab pyautogui mss screen capture",
			Remediation: "禁止屏幕截图行为",
		},

		// 剪贴板访问
		{
			ID:          "vuln-clipboard",
			Name:        "剪贴板窃取模式",
			Category:    "data_collection",
			Severity:    "中风险",
			Description: "读取剪贴板内容，可能窃取密码等敏感信息",
			CodePattern: "clipboard pyperclip paste copy xclip xsel win32clipboard",
			Remediation: "限制剪贴板访问权限",
		},

		// 特权提升
		{
			ID:          "vuln-privesc",
			Name:        "特权提升模式",
			Category:    "unsafe",
			Severity:    "高风险",
			Description: "尝试提升权限，如 SUID、sudo、setuid 等",
			CodePattern: "sudo setuid setgid suid chmod +s chown root privilege escalate",
			Remediation: "禁止权限提升操作",
		},

		// 容器逃逸
		{
			ID:          "vuln-container-escape",
			Name:        "容器逃逸模式",
			Category:    "unsafe",
			Severity:    "高风险",
			Description: "尝试逃逸容器环境，如挂载宿主机文件系统",
			CodePattern: "docker.sock /proc/1/ns mount cgroup escape breakout chroot pivot_root",
			Remediation: "禁止容器逃逸行为",
		},

		// 内存操作
		{
			ID:          "vuln-memory-manipulation",
			Name:        "内存操作模式",
			Category:    "unsafe",
			Severity:    "高风险",
			Description: "直接操作内存，如 ctypes、mmap、指针操作等",
			CodePattern: "ctypes pointer mmap VirtualAlloc WriteProcessMemory ReadProcessMemory inject",
			Remediation: "禁止直接内存操作",
		},

		// 加密货币钱包窃取
		{
			ID:          "vuln-wallet-steal",
			Name:        "加密货币钱包窃取",
			Category:    "data_collection",
			Severity:    "高风险",
			Description: "读取加密货币钱包文件或私钥",
			CodePattern: "wallet keystore private_key mnemonic seed_phrase ethereum bitcoin crypto metamask",
			Remediation: "禁止读取钱包文件",
		},

		// 环境变量批量收集
		{
			ID:          "vuln-env-collect",
			Name:        "环境变量批量收集",
			Category:    "data_collection",
			Severity:    "高风险",
			Description: "批量读取环境变量，可能收集 API 密钥等敏感信息",
			CodePattern: "os.environ os.getenv process.env env keys items API_KEY SECRET TOKEN PASSWORD",
			Remediation: "限制环境变量访问范围",
		},
	}
}

// =============================================================================
// 辅助函数
// =============================================================================

// extractFunctionCode 提取函数的代码文本。
func extractFunctionCode(file File, fn Function) string {
	lines := strings.Split(file.RawContent, "\n")
	if fn.StartLine <= 0 || fn.EndLine <= 0 || fn.StartLine > len(lines) {
		return fn.Name
	}
	start := fn.StartLine - 1
	end := fn.EndLine
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

// truncate 截断字符串。
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// CosineSimilarity 计算余弦相似度（内部使用）。
func CosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dotProduct, normA, normB float64
	for i := range a {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}

// FormatSimilarityMatch 格式化匹配结果。
func FormatSimilarityMatch(m SimilarityMatch) string {
	return fmt.Sprintf("[%s] %s (相似度=%.0f%%) at %s", m.Severity, m.PatternName, m.Similarity*100, m.Location)
}
