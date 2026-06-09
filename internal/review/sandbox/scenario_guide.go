package sandbox

import (
	"strings"

	"skill-scanner/internal/logx"
)

// =============================================================================
// 场景引导执行 (Scenario-Guided Execution)
//
// 根据技能的声明场景构造测试输入，引导沙箱执行。
// 不是随机执行入口点，而是根据技能"应该做什么"来验证"实际做了什么"。
//
// 流程：
//   1. 从 SKILL.md / 描述中提取场景信息
//   2. 根据场景类型生成测试输入
//   3. 用场景输入执行技能
//   4. 监控实际行为是否偏离声明场景
// =============================================================================

// SkillScenario 技能场景信息。
type SkillScenario struct {
	// Type 场景类型
	Type ScenarioType `json:"type"`
	// Description 场景描述
	Description string `json:"description"`
	// InputTemplate 测试输入模板
	InputTemplate string `json:"input_template"`
	// ExpectedBehavior 预期行为
	ExpectedBehavior string `json:"expected_behavior"`
	// RiskIndicators 风险指标（偏离场景的信号）
	RiskIndicators []string `json:"risk_indicators"`
}

// ScenarioType 场景类型。
type ScenarioType string

const (
	ScenarioChat          ScenarioType = "chat"           // 对话/问答
	ScenarioTranslator    ScenarioType = "translator"      // 翻译
	ScenarioCodeReview    ScenarioType = "code_review"     // 代码审查
	ScenarioDataProcess   ScenarioType = "data_process"    // 数据处理
	ScenarioFileOperation ScenarioType = "file_operation"  // 文件操作
	ScenarioWebScrape     ScenarioType = "web_scrape"      // 网页抓取
	ScenarioAPI           ScenarioType = "api"             // API 调用
	ScenarioAutomation    ScenarioType = "automation"       // 自动化任务
	ScenarioUnknown       ScenarioType = "unknown"         // 未知场景
)

// ScenarioGuide 场景引导器。
type ScenarioGuide struct {
	scenarios []SkillScenario
}

// NewScenarioGuide 创建场景引导器。
func NewScenarioGuide() *ScenarioGuide {
	return &ScenarioGuide{
		scenarios: buildDefaultScenarios(),
	}
}

// AnalyzeSkill 分析技能场景。
func (g *ScenarioGuide) AnalyzeSkill(skillName, description, skillMD string) []SkillScenario {
	var scenarios []SkillScenario

	combined := strings.ToLower(skillName + " " + description + " " + skillMD)

	// 匹配场景类型
	for _, scenario := range g.scenarios {
		if g.matchesScenario(combined, scenario.Type) {
			scenarios = append(scenarios, scenario)
		}
	}

	// 如果没有匹配到，返回通用场景
	if len(scenarios) == 0 {
		scenarios = append(scenarios, SkillScenario{
			Type:             ScenarioUnknown,
			Description:      "通用测试场景",
			InputTemplate:    "hello\nhelp\nstatus\nquit",
			ExpectedBehavior: "技能应正常响应，不执行危险操作",
			RiskIndicators:   []string{"网络外发", "文件写入", "命令执行"},
		})
	}

	return scenarios
}

// GenerateTestInputs 根据场景生成测试输入。
func (g *ScenarioGuide) GenerateTestInputs(scenario SkillScenario) []string {
	switch scenario.Type {
	case ScenarioChat:
		return []string{
			"你好，请介绍一下你的功能",
			"帮我处理一下这段文本",
			"quit",
		}
	case ScenarioTranslator:
		return []string{
			"Hello, how are you?",
			"请将这段话翻译成英文：今天天气很好",
			"This is a test sentence for translation.",
		}
	case ScenarioCodeReview:
		return []string{
			"def hello():\n    print('hello')\n",
			"请审查这段代码的安全性",
			"function test() { return eval('1+1'); }",
		}
	case ScenarioDataProcess:
		return []string{
			"name,age\nAlice,30\nBob,25",
			"请处理这份数据",
			`{"key": "value", "count": 42}`,
		}
	case ScenarioFileOperation:
		return []string{
			"请读取当前目录的文件列表",
			"创建一个测试文件",
			"查看文件内容",
		}
	case ScenarioWebScrape:
		return []string{
			"https://example.com",
			"请抓取这个网页的内容",
			"https://httpbin.org/get",
		}
	case ScenarioAPI:
		return []string{
			"请调用 API 获取数据",
			`{"method": "GET", "url": "https://httpbin.org/get"}`,
			"测试 API 连接",
		}
	case ScenarioAutomation:
		return []string{
			"请执行自动化任务",
			"列出当前目录文件",
			"检查系统状态",
		}
	default:
		return []string{
			"hello",
			"help",
			"test input",
		}
	}
}

// matchesScenario 检查文本是否匹配场景类型。
func (g *ScenarioGuide) matchesScenario(text string, scenarioType ScenarioType) bool {
	switch scenarioType {
	case ScenarioChat:
		return scenarioContainsAny(text, "chat", "对话", "问答", "聊天", "assistant", "助手", "ai", "智能")
	case ScenarioTranslator:
		return scenarioContainsAny(text, "translat", "翻译", "翻譯", "语言", "language", "多语")
	case ScenarioCodeReview:
		return scenarioContainsAny(text, "code review", "代码审查", "代码检查", "code audit", "安全审查", "lint")
	case ScenarioDataProcess:
		return scenarioContainsAny(text, "data", "数据", "csv", "json", "parse", "处理", "分析", "转换")
	case ScenarioFileOperation:
		return scenarioContainsAny(text, "file", "文件", "read", "write", "读取", "写入", "存储", "管理")
	case ScenarioWebScrape:
		return scenarioContainsAny(text, "scrape", "crawl", "抓取", "爬虫", "web", "网页", "fetch", "下载")
	case ScenarioAPI:
		return scenarioContainsAny(text, "api", "接口", "request", "请求", "http", "rest", "grpc")
	case ScenarioAutomation:
		return scenarioContainsAny(text, "automat", "自动", "脚本", "script", "task", "任务", "pipeline", "workflow")
	default:
		return false
	}
}

// scenarioContainsAny 检查文本是否包含任意关键词。
func scenarioContainsAny(text string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(text, kw) {
			return true
		}
	}
	return false
}

// buildDefaultScenarios 构建默认场景。
func buildDefaultScenarios() []SkillScenario {
	return []SkillScenario{
		{
			Type:             ScenarioChat,
			Description:      "对话/问答场景",
			InputTemplate:    "你好\n请问你能做什么\nquit",
			ExpectedBehavior: "技能应正常响应用户问题，不执行代码或网络操作",
			RiskIndicators:   []string{"eval", "exec", "requests.post", "os.system", "subprocess"},
		},
		{
			Type:             ScenarioTranslator,
			Description:      "翻译场景",
			InputTemplate:    "Hello, how are you?\n请翻译这段话",
			ExpectedBehavior: "技能应返回翻译结果，不应访问网络或文件系统",
			RiskIndicators:   []string{"requests", "urllib", "fetch", "axios", "open(", "write"},
		},
		{
			Type:             ScenarioCodeReview,
			Description:      "代码审查场景",
			InputTemplate:    "def hello(): print('hello')\n请检查这段代码",
			ExpectedBehavior: "技能应分析代码并给出建议，不应执行代码",
			RiskIndicators:   []string{"eval", "exec", "compile", "os.system", "subprocess"},
		},
		{
			Type:             ScenarioDataProcess,
			Description:      "数据处理场景",
			InputTemplate:    "name,age\nAlice,30\nBob,25",
			ExpectedBehavior: "技能应处理数据并返回结果，不应外发数据",
			RiskIndicators:   []string{"requests.post", "urllib", "fetch", "axios", "socket"},
		},
		{
			Type:             ScenarioFileOperation,
			Description:      "文件操作场景",
			InputTemplate:    "请列出当前目录文件",
			ExpectedBehavior: "技能应操作声明的文件范围，不应访问敏感路径",
			RiskIndicators:   []string{"/etc/passwd", "/root", ".ssh", "id_rsa", ".env", "credential"},
		},
		{
			Type:             ScenarioWebScrape,
			Description:      "网页抓取场景",
			InputTemplate:    "https://example.com",
			ExpectedBehavior: "技能应抓取目标网页，不应向非目标服务器发送数据",
			RiskIndicators:   []string{"POST", "upload", "send", "exfil", "c2", "beacon"},
		},
		{
			Type:             ScenarioAPI,
			Description:      "API 调用场景",
			InputTemplate:    `{"method": "GET", "url": "https://httpbin.org/get"}`,
			ExpectedBehavior: "技能应调用声明的 API，不应访问未声明的端点",
			RiskIndicators:   []string{"eval", "exec", "os.system", "subprocess", "upload", "send"},
		},
		{
			Type:             ScenarioAutomation,
			Description:      "自动化任务场景",
			InputTemplate:    "请执行自动化任务",
			ExpectedBehavior: "技能应执行声明的任务，不应执行未声明的操作",
			RiskIndicators:   []string{"crontab", "systemd", "autostart", "registry", "persistence"},
		},
	}
}

// ScenarioExecutionResult 场景执行结果。
type ScenarioExecutionResult struct {
	Scenario    SkillScenario `json:"scenario"`
	Inputs      []string      `json:"inputs"`
	Outputs     []string      `json:"outputs"`
	Deviations  []string      `json:"deviations"`  // 偏离场景的信号
	RiskLevel   string        `json:"risk_level"`   // clean / suspicious / malicious
}

// AnalyzeDeviations 分析执行结果是否偏离场景。
func (g *ScenarioGuide) AnalyzeDeviations(scenario SkillScenario, outputs []string) []string {
	var deviations []string

	for _, output := range outputs {
		lower := strings.ToLower(output)
		for _, indicator := range scenario.RiskIndicators {
			if strings.Contains(lower, strings.ToLower(indicator)) {
				deviations = append(deviations, "检测到风险指标: "+indicator)
			}
		}
	}

	return deviations
}

// BuildScenarioCommand 根据场景构建执行命令。
func BuildScenarioCommand(scenario SkillScenario, entrypoint string) string {
	inputs := strings.Join(strings.Split(scenario.InputTemplate, "\n"), "\\n")
	return "echo -e '" + inputs + "' | " + entrypoint
}

// LogScenarioAnalysis 记录场景分析日志。
func LogScenarioAnalysis(scenarios []SkillScenario) {
	for _, s := range scenarios {
		logx.With(
			"component", "scenario_guide",
			"type", string(s.Type),
			"description", s.Description,
		).Info("scenario identified")
	}
}
