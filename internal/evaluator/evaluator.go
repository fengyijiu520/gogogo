package evaluator

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"skill-scanner/internal/analyzer"
	"skill-scanner/internal/config"
	"skill-scanner/internal/embedder"
	"skill-scanner/internal/llm"
	"skill-scanner/internal/similarity"
)

// Dependency 技能依赖项
type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SourceFile 源代码文件
type SourceFile struct {
	Path                string `json:"path"`
	Content             string `json:"content"`
	PreprocessedContent string `json:"preprocessed_content,omitempty"`
	Language            string `json:"language"`
}

func (f SourceFile) AnalysisContent() string {
	if strings.TrimSpace(f.PreprocessedContent) == "" {
		return f.Content
	}
	return f.Content + "\n\n" + f.PreprocessedContent
}

// Skill 待审查的技能信息
type Skill struct {
	Name         string       `json:"name"`
	Description  string       `json:"description"`
	Code         string       `json:"code"`
	Files        []SourceFile `json:"files"`
	Dependencies []Dependency `json:"dependencies"`
	Permissions  []string     `json:"permissions"`
}

// EvaluationResult 审查结果
type EvaluationResult struct {
	Passed         bool                         `json:"passed"`
	Score          float64                      `json:"score"`
	P0Blocked      bool                         `json:"p0_blocked"`
	P0Reasons      []string                     `json:"p0_reasons"`
	ItemScores     map[string]float64           `json:"item_scores"`
	RiskLevel      string                       `json:"risk_level"`
	Analysis       *analyzer.CodeAnalysisResult `json:"analysis,omitempty"`
	IntentAnalysis *llm.AnalysisResult          `json:"intent_analysis,omitempty"`
	FindingDetails []FindingDetail              `json:"finding_details,omitempty"`
}

// FindingDetail 详细发现项
type FindingDetail struct {
	RuleID      string
	Severity    string
	Title       string
	Description string
	Location    string
	CodeSnippet string
}

// Thresholds 内部兼容阈值配置
type Thresholds struct {
	PassScore      float64
	ReviewScore    float64
	SimilarityLow  float64
	SimilarityHigh float64
}

// CacheItem 缓存项
type CacheItem struct {
	Result   *EvaluationResult
	ExpireAt time.Time
}

// Evaluator 技能审查引擎
type Evaluator struct {
	embedder   embedder.Embedder
	llmClient  llm.Client
	config     *config.Config
	funcMap    map[string]DetectionFunc
	thresholds Thresholds
	cache      map[string]CacheItem
	cacheMutex sync.RWMutex
}

// DetectionFunc 检测函数签名
type DetectionFunc func(skill *Skill, rule config.Rule) (score float64, blocked bool, reason string, details []FindingDetail)

// Rule 审查规则接口
type Rule interface {
	Evaluate(ctx context.Context, skill *Skill) (score float64, reason string, blocked bool)
}

var DefaultThresholds = Thresholds{
	PassScore:      80,
	ReviewScore:    60,
	SimilarityLow:  config.SimilarityThresholdLow(),
	SimilarityHigh: config.SimilarityThresholdHigh(),
}

// NewEvaluator 创建新的审查引擎
func NewEvaluator(embedder embedder.Embedder, llmClient llm.Client, cfg *config.Config) *Evaluator {
	e := &Evaluator{
		embedder:   embedder,
		llmClient:  llmClient,
		config:     cfg,
		funcMap:    make(map[string]DetectionFunc),
		thresholds: DefaultThresholds,
		cache:      make(map[string]CacheItem),
	}
	e.registerBuiltinFuncs()
	return e
}

func (e *Evaluator) registerBuiltinFuncs() {
	e.funcMap["detectDataExfiltration"] = e.detectDataExfiltrationFunc
	e.funcMap["detectHardcodedCredential"] = e.detectHardcodedCredentialFunc
	e.funcMap["detectMCPAbuse"] = e.detectMCPAbuseFunc
	e.funcMap["detectEnvironmentEvasion"] = e.detectEnvironmentEvasionFunc
	e.funcMap["evaluateIrreversibleOpsApproval"] = e.evaluateIrreversibleOpsApprovalFunc
	e.funcMap["evaluateDataMinimizationEvidence"] = e.evaluateDataMinimizationEvidenceFunc
	e.funcMap["evaluateDependencyVulns"] = e.evaluateDependencyVulnsFunc
	e.funcMap["evaluatePermissions"] = e.evaluatePermissionsFunc
	e.funcMap["evaluateInjectionRisk"] = e.evaluateInjectionRiskFunc
	e.funcMap["evaluateToolResponsePoisoning"] = e.evaluateToolResponsePoisoningFunc
	e.funcMap["evaluateContextLeak"] = e.evaluateContextLeakFunc
	e.funcMap["evaluateSoftDependencies"] = e.evaluateSoftDependenciesFunc
	e.funcMap["evaluateCredentialIsolation"] = e.evaluateCredentialIsolationFunc
	e.funcMap["evaluateHiddenContent"] = e.evaluateHiddenContentFunc
	e.funcMap["evaluateResourceRisk"] = e.evaluateResourceRiskFunc
	e.funcMap["evaluateMemoryIsolation"] = e.evaluateMemoryIsolationFunc
	e.funcMap["evaluateSSRFProtection"] = e.evaluateSSRFProtectionFunc
	e.funcMap["evaluateLicenseValidationConfig"] = e.evaluateLicenseValidationConfigFunc
	e.funcMap["evaluatePathTraversal"] = e.evaluatePathTraversalFunc
	e.funcMap["evaluateInputSchema"] = e.evaluateInputSchemaFunc
	e.funcMap["evaluateAuditLogging"] = e.evaluateAuditLoggingFunc
	e.funcMap["evaluateSBOMVersionLock"] = e.evaluateSBOMVersionLockFunc
	e.funcMap["evaluateTLSProtection"] = e.evaluateTLSProtectionFunc
	e.funcMap["evaluateFileUploadParsing"] = e.evaluateFileUploadParsingFunc
	e.funcMap["evaluateUnsafeDeserialization"] = e.evaluateUnsafeDeserializationFunc
	e.funcMap["evaluateDebugBackdoor"] = e.evaluateDebugBackdoorFunc
}

func (e *Evaluator) SetThresholds(t Thresholds) {
	e.thresholds = t
}

type CacheKey struct {
	CodeHash        string
	DescHash        string
	DepsHash        string
	PermissionsHash string
}

func (c *CacheKey) String() string {
	return fmt.Sprintf("eval:%s:%s:%s:%s", c.CodeHash[:8], c.DescHash[:8], c.DepsHash[:8], c.PermissionsHash[:8])
}

func generateCacheKey(skill *Skill) CacheKey {
	var filesContent strings.Builder
	for _, file := range skill.Files {
		filesContent.WriteString(file.Path)
		filesContent.WriteString(file.AnalysisContent())
	}
	codeHash := sha256.Sum256([]byte(filesContent.String()))
	descHash := sha256.Sum256([]byte(skill.Description))
	depsStr := fmt.Sprintf("%v", skill.Dependencies)
	depsHash := sha256.Sum256([]byte(depsStr))
	permStr := fmt.Sprintf("%v", skill.Permissions)
	permHash := sha256.Sum256([]byte(permStr))
	return CacheKey{
		CodeHash:        hex.EncodeToString(codeHash[:]),
		DescHash:        hex.EncodeToString(descHash[:]),
		DepsHash:        hex.EncodeToString(depsHash[:]),
		PermissionsHash: hex.EncodeToString(permHash[:]),
	}
}

// EvaluateWithCascade 级联审查
func (e *Evaluator) EvaluateWithCascade(ctx context.Context, skill *Skill) (*EvaluationResult, error) {
	cacheKey := generateCacheKey(skill)
	cacheStr := cacheKey.String()
	e.cacheMutex.RLock()
	if item, ok := e.cache[cacheStr]; ok && item.ExpireAt.After(time.Now()) {
		e.cacheMutex.RUnlock()
		return item.Result, nil
	}
	e.cacheMutex.RUnlock()

	result := &EvaluationResult{
		Passed:     true,
		Score:      100,
		ItemScores: make(map[string]float64),
		RiskLevel:  "low",
		Analysis:   e.runStaticAnalysis(skill),
	}

	blocked := false

	// 1. 执行 P0 阻断层规则（合并相邻行，去重文件）
	detailMap := make(map[string]*FindingDetail) // 键：文件路径+规则ID
	reasonSet := make(map[string]bool)

	for _, rule := range e.config.Rules {
		if rule.Layer != "P0" {
			continue
		}
		if rule.Detection.Type == "pattern" {
			// 按文件分组匹配行
			matchedAny := false
			for _, file := range skill.Files {
				lines := strings.Split(file.AnalysisContent(), "\n")
				matchedLines := make(map[int]bool) // 记录哪些行匹配
				for lineNum, line := range lines {
					for _, pat := range rule.Detection.Patterns {
						re := regexp.MustCompile(pat)
						if re.MatchString(line) {
							matchedLines[lineNum] = true
							break // 只要匹配一个模式即可
						}
					}
				}

				if len(matchedLines) == 0 {
					continue
				}
				matchedAny = true

				// 将连续行合并为区间
				var intervals [][2]int
				var start, end int
				inBlock := false
				for i := 0; i < len(lines); i++ {
					if matchedLines[i] {
						if !inBlock {
							start = i
							inBlock = true
						}
						end = i
					} else {
						if inBlock {
							intervals = append(intervals, [2]int{start, end})
							inBlock = false
						}
					}
				}
				if inBlock {
					intervals = append(intervals, [2]int{start, end})
				}

				// 为每个区间生成一条 FindingDetail
				for _, interval := range intervals {
					startLine := interval[0]
					endLine := interval[1]

					// 代码上下文：从 startLine-2 到 endLine+2
					contextStart := startLine - 2
					if contextStart < 0 {
						contextStart = 0
					}
					contextEnd := endLine + 3
					if contextEnd > len(lines) {
						contextEnd = len(lines)
					}

					var codeBuilder strings.Builder
					for i := contextStart; i < contextEnd; i++ {
						prefix := "  "
						if i >= startLine && i <= endLine {
							prefix = "> "
						}
						codeBuilder.WriteString(fmt.Sprintf("%s%4d | %s\n", prefix, i+1, lines[i]))
					}

					// 生成唯一键（文件+规则ID+起始行，确保同一区间不重复）
					key := fmt.Sprintf("%s:%s:%d", file.Path, rule.ID, startLine)
					if _, exists := detailMap[key]; !exists {
						loc := fmt.Sprintf("%s:%d", filepath.Base(file.Path), startLine+1)
						if endLine > startLine {
							loc = fmt.Sprintf("%s:%d-%d", filepath.Base(file.Path), startLine+1, endLine+1)
						}
						detailMap[key] = &FindingDetail{
							RuleID:      rule.ID,
							Severity:    "高风险",
							Title:       rule.Name,
							Description: rule.OnFail.Reason,
							Location:    loc,
							CodeSnippet: codeBuilder.String(),
						}
					}

					if rule.OnFail.Action == "block" {
						blocked = true
						result.P0Blocked = true
						if !reasonSet[rule.OnFail.Reason] {
							reasonSet[rule.OnFail.Reason] = true
							result.P0Reasons = append(result.P0Reasons, rule.OnFail.Reason)
						}
					}
				}
			}
			if matchedAny {
				result.ItemScores[rule.ID] = 0
			} else {
				result.ItemScores[rule.ID] = rule.Weight
			}
			continue
		}
		// 其他类型保持原有调用方式
		score, ruleBlocked, reason, details := e.executeRule(ctx, skill, rule)
		if len(details) > 0 {
			result.FindingDetails = append(result.FindingDetails, details...)
		}
		if len(details) > 0 && rule.OnFail.Action == "block" {
			ruleBlocked = true
			if reason == "" {
				reason = rule.OnFail.Reason
			}
		}
		if ruleBlocked {
			blocked = true
			result.P0Blocked = true
			if !reasonSet[reason] {
				reasonSet[reason] = true
				result.P0Reasons = append(result.P0Reasons, reason)
			}
		}
		result.ItemScores[rule.ID] = score
	}

	// 将合并后的详情存入 result
	for _, detail := range detailMap {
		result.FindingDetails = append(result.FindingDetails, *detail)
	}

	// 2. LLM 深度分析
	ruleByID := buildRuleLookup(e.config.Rules)
	if detail, staticBlocked := e.buildStaticIntentAlignmentFinding(skill, ruleByID); detail != nil {
		result.FindingDetails = append(result.FindingDetails, *detail)
		if staticBlocked {
			blocked = true
			result.P0Blocked = true
			if !reasonSet[detail.Description] {
				reasonSet[detail.Description] = true
				result.P0Reasons = append(result.P0Reasons, detail.Description)
			}
		}
	}
	if details, staticBlocked := e.buildStaticSkillAuditFindings(skill, ruleByID); len(details) > 0 {
		result.FindingDetails = append(result.FindingDetails, details...)
		if staticBlocked {
			blocked = true
			result.P0Blocked = true
			for _, detail := range details {
				if detail.Severity != "高风险" {
					continue
				}
				if !reasonSet[detail.Description] {
					reasonSet[detail.Description] = true
					result.P0Reasons = append(result.P0Reasons, detail.Description)
				}
			}
		}
	}
	if e.llmClient != nil {
		codeSummary := extractCodeSummaryFromFiles(skill.Files)
		llmResult, err := e.llmClient.AnalyzeCode(ctx, skill.Name, skill.Description, codeSummary)
		if err == nil && llmResult != nil {
			result.IntentAnalysis = llmResult
			if detail, llmBlocked := buildLLMIntentFinding(llmResult, ruleByID); detail != nil {
				result.FindingDetails = append(result.FindingDetails, *detail)
				if llmBlocked {
					blocked = true
					result.P0Blocked = true
					if !reasonSet[detail.Description] {
						reasonSet[detail.Description] = true
						result.P0Reasons = append(result.P0Reasons, detail.Description)
					}
				}
			}
			seen := make(map[string]bool)
			for _, risk := range llmResult.Risks {
				risk = normalizeLLMRisk(risk)
				loc, snippet, found := e.locateRiskInFiles(skill, risk)
				if !found {
					continue // 无具体位置，不生成该项
				}
				key := risk.Title + "|" + loc
				if seen[key] {
					continue
				}
				seen[key] = true

				ruleID := "LLM-DETECT"
				title := fmt.Sprintf("LLM检测: %s", risk.Title)
				if mappedID, ok := mapLLMRiskToRuleID(risk, ruleByID); ok {
					ruleID = mappedID
					title = ruleByID[mappedID].Name
				}

				severity := "高风险"
				if risk.Severity == "high" {
					severity = "高风险"
					if ruleID == "LLM-DETECT" {
						blocked = true
						result.P0Blocked = true
						result.P0Reasons = append(result.P0Reasons, fmt.Sprintf("LLM深度检测: %s - %s", risk.Title, risk.Description))
					}
				} else if risk.Severity == "medium" {
					severity = "中风险"
				} else {
					severity = "低风险"
				}

				detail := FindingDetail{
					RuleID:      ruleID,
					Severity:    severity,
					Title:       title,
					Description: risk.Description,
					Location:    loc,
					CodeSnippet: snippet,
				}
				result.FindingDetails = append(result.FindingDetails, detail)
			}
		}
	}

	// 3. P1 层
	for _, rule := range e.config.Rules {
		if rule.Layer != "P1" {
			continue
		}
		score, _, _, details := e.executeRule(ctx, skill, rule)
		result.ItemScores[rule.ID] = score
		if len(details) > 0 {
			result.FindingDetails = append(result.FindingDetails, details...)
		}
	}

	// 4. P2 层
	for _, rule := range e.config.Rules {
		if rule.Layer != "P2" {
			continue
		}
		score, _, _, details := e.executeRule(ctx, skill, rule)
		result.ItemScores[rule.ID] = score
		if len(details) > 0 {
			result.FindingDetails = append(result.FindingDetails, details...)
		}
	}

	result.RiskLevel = aggregateEvaluationRisk(result.FindingDetails, blocked)
	result.Score = 0
	result.Passed = result.RiskLevel == "low"
	if result.RiskLevel == "high" && blocked {
		result.P0Blocked = true
	}

	e.cacheResult(cacheStr, result)
	return result, nil
}

func buildLLMIntentFinding(result *llm.AnalysisResult, rules map[string]config.Rule) (*FindingDetail, bool) {
	if result == nil {
		return nil, false
	}
	riskLevel := normalizeLLMIntentRiskLevel(result.IntentRiskLevel)
	if riskLevel == "" || riskLevel == "none" {
		return nil, false
	}
	ruleID := "V7-006"
	title := "技能声明与实际行为一致性"
	if rule, ok := rules[ruleID]; ok && strings.TrimSpace(rule.Name) != "" {
		title = rule.Name
	}
	severity := "低风险"
	blocked := false
	switch riskLevel {
	case "high":
		severity = "高风险"
		blocked = true
	case "medium":
		severity = "中风险"
	default:
		severity = "低风险"
	}
	desc := strings.TrimSpace(result.IntentMismatch)
	if desc == "" {
		desc = "LLM 语义判断显示声明意图与实际行为存在不一致。"
	}
	snippetParts := []string{
		"声明语义: " + defaultText(result.StatedIntent, "未提供"),
		"实际行为: " + defaultText(result.ActualBehavior, "未提供"),
	}
	if len(result.DeclaredCapabilities) > 0 {
		snippetParts = append(snippetParts, "声明能力: "+strings.Join(result.DeclaredCapabilities, "、"))
	}
	if len(result.ActualCapabilities) > 0 {
		snippetParts = append(snippetParts, "实际能力: "+strings.Join(result.ActualCapabilities, "、"))
	}
	if len(result.ConsistencyEvidence) > 0 {
		snippetParts = append(snippetParts, "一致性证据: "+strings.Join(result.ConsistencyEvidence, "；"))
	}
	return &FindingDetail{
		RuleID:      ruleID,
		Severity:    severity,
		Title:       title,
		Description: desc,
		Location:    "技能声明与实际行为语义比对",
		CodeSnippet: strings.Join(snippetParts, "\n"),
	}, blocked
}

func (e *Evaluator) buildStaticIntentAlignmentFinding(skill *Skill, rules map[string]config.Rule) (*FindingDetail, bool) {
	rule, ok := rules["V7-006"]
	if !ok {
		return nil, false
	}
	declaredText := strings.ToLower(skill.Name + "\n" + skill.Description)
	for _, file := range skill.Files {
		base := strings.ToLower(filepath.Base(file.Path))
		if base == "skill.md" || strings.HasPrefix(base, "readme") {
			declaredText += "\n" + strings.ToLower(file.AnalysisContent())
		}
	}
	declaresNetwork := containsAny(declaredText, "network", "http", "api", "url", "web", "download", "fetch", "requests", "联网", "网络", "接口", "外部", "下载")
	declaresCommand := containsAny(declaredText, "command", "shell", "exec", "subprocess", "terminal", "命令", "终端", "执行脚本", "运行脚本")
	declaresSensitiveFile := containsAny(declaredText, "credential", "token", "secret", "ssh", "home", "documents", "download", "file", "凭据", "密钥", "令牌", "文件", "文档")

	patterns := []struct {
		declared bool
		match    func(string) bool
		desc     string
	}{
		{declaresCommand, looksLikeCommandExecution, "声明未提及命令执行，但可执行代码包含 shell/子进程调用"},
		{declaresNetwork, looksLikeNetworkExecution, "声明未提及网络访问，但可执行代码包含外联或下载能力"},
		{declaresSensitiveFile, looksLikeSensitiveCredentialAccess, "声明未提及敏感文件或用户目录访问，但代码包含真实敏感位置或凭据读取行为"},
	}

	for _, file := range skill.Files {
		if !isProductionSourceFile(file.Path) {
			continue
		}
		lines := strings.Split(file.AnalysisContent(), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isCommentLikeLine(trimmed) {
				continue
			}
			for _, p := range patterns {
				if p.declared || !p.match(trimmed) {
					continue
				}
				return &FindingDetail{
					RuleID:      "V7-006",
					Severity:    "高风险",
					Title:       defaultText(rule.Name, "技能声明与实际行为一致性"),
					Description: p.desc,
					Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
					CodeSnippet: formatCodeContext(lines, i, 2),
				}, rule.OnFail.Action == "block"
			}
		}
	}
	return nil, false
}

func (e *Evaluator) buildStaticSkillAuditFindings(skill *Skill, rules map[string]config.Rule) ([]FindingDetail, bool) {
	rule, ok := rules["V7-006"]
	if !ok || !isAgentSkillProject(skill) {
		return nil, false
	}

	declaredText := collectDeclaredSkillText(skill)
	declaresNetwork := containsAny(declaredText, "network", "http", "api", "url", "web", "download", "fetch", "requests", "联网", "网络", "接口", "外部", "下载")
	declaresCommand := containsAny(declaredText, "command", "shell", "exec", "subprocess", "terminal", "命令", "终端", "执行脚本", "运行脚本")
	declaresSensitiveFile := containsAny(declaredText, "credential", "token", "secret", "ssh", "env", "home", "file", "凭据", "密钥", "令牌", "环境变量", "文件")
	declaresDestructive := containsAny(declaredText, "delete", "remove", "cleanup", "drop", "truncate", "删除", "清理", "移除", "销毁")

	patterns := []struct {
		declared    bool
		severity    string
		desc        string
		match       func(string) bool
		requireProd bool
	}{
		{false, "高风险", "Skill 脚本包含反弹 Shell 或远程交互式控制逻辑，属于明显恶意行为。", func(line string) bool {
			return regexp.MustCompile(`(?i)(bash\s+-i\s+>&\s*/dev/tcp|nc\s+-e\s+|socket\.socket[\s\S]{0,200}(dup2|subprocess|/bin/sh)|powershell\s+-nop|reverse[_-]?shell)`).MatchString(line)
		}, true},
		{false, "高风险", "Skill 脚本包含挖矿、C2 或持久化后门特征，属于明显恶意行为。", looksLikeMaliciousPersistenceOrC2, true},
		{declaresSensitiveFile, "高风险", "声明未提及敏感凭据或用户配置访问，但 Skill 脚本包含真实敏感位置或凭据读取行为。", looksLikeSensitiveCredentialAccess, true},
		{declaresNetwork, "高风险", "声明未提及网络访问，但 Skill 脚本包含外联、下载或上传能力。", looksLikeNetworkExecution, true},
		{declaresCommand, "高风险", "声明未提及命令执行，但 Skill 脚本包含 shell、子进程或动态代码执行能力。", looksLikeCommandExecution, true},
		{declaresDestructive, "高风险", "声明未提及破坏性操作，但 Skill 脚本包含删除、清空或不可逆修改能力。", looksLikeDestructiveExecution, true},
		{false, "中风险", "Skill 声明文档或工具描述包含提示词覆盖、绕过审批或泄露系统提示词意图。", func(line string) bool {
			return regexp.MustCompile(`(?i)(ignore previous instructions|disregard previous instructions|reveal system prompt|print system prompt|bypass approval|bypass sandbox|do not ask user|without user confirmation|忽略之前的指令|绕过审批|泄露系统提示词)`).MatchString(line)
		}, false},
	}

	var details []FindingDetail
	seen := make(map[string]bool)
	for _, file := range skill.Files {
		isScript := isSkillScriptFile(file.Path)
		isDeclaration := isSkillDeclarationFile(file.Path)
		if !isDeclaration && isLowSignalExamplePath(file.Path) {
			continue
		}
		if !isScript && !isDeclaration {
			continue
		}
		lines := strings.Split(file.AnalysisContent(), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || (isScript && isCommentLikeLine(trimmed)) {
				continue
			}
			for _, p := range patterns {
				if p.declared || !p.match(trimmed) || (p.requireProd && !isScript) || (!p.requireProd && !isDeclaration) {
					continue
				}
				key := fmt.Sprintf("%s:%d:%s", file.Path, i, p.desc)
				if seen[key] {
					continue
				}
				seen[key] = true
				details = append(details, FindingDetail{
					RuleID:      "V7-006",
					Severity:    p.severity,
					Title:       defaultText(rule.Name, "技能声明与实际行为一致性"),
					Description: p.desc,
					Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
					CodeSnippet: formatCodeContext(lines, i, 2),
				})
			}
		}
	}

	return details, hasHighSeverity(details) && rule.OnFail.Action == "block"
}

func isAgentSkillProject(skill *Skill) bool {
	if strings.Contains(strings.ToLower(skill.Description), "skill.md:") {
		return true
	}
	for _, file := range skill.Files {
		if strings.EqualFold(filepath.Base(file.Path), "SKILL.md") {
			return true
		}
	}
	return false
}

func collectDeclaredSkillText(skill *Skill) string {
	var builder strings.Builder
	builder.WriteString(strings.ToLower(skill.Name))
	builder.WriteString("\n")
	builder.WriteString(strings.ToLower(skill.Description))
	for _, file := range skill.Files {
		if isSkillDeclarationFile(file.Path) {
			builder.WriteString("\n")
			builder.WriteString(strings.ToLower(file.AnalysisContent()))
		}
	}
	return builder.String()
}

func isSkillDeclarationFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return base == "skill.md" || base == "readme.md" || base == "description.md" || base == "manifest.md"
}

func isSkillScriptFile(path string) bool {
	normalized := strings.ToLower(filepath.ToSlash(path))
	if strings.Contains(normalized, "/scripts/") || strings.HasPrefix(normalized, "scripts/") {
		return isProductionSourceFile(path)
	}
	return false
}

func hasHighSeverity(details []FindingDetail) bool {
	for _, detail := range details {
		if detail.Severity == "高风险" {
			return true
		}
	}
	return false
}

func normalizeLLMIntentRiskLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "高风险", "high", "critical", "block":
		return "high"
	case "中风险", "medium", "review":
		return "medium"
	case "低风险", "low":
		return "low"
	case "无风险", "none", "pass", "":
		return "none"
	default:
		return ""
	}
}

func defaultText(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func formatLLMObfuscationSnippet(result *llm.ObfuscationAnalysisResult) string {
	if result == nil {
		return ""
	}
	parts := make([]string, 0, 6)
	if result.Technique != "" {
		parts = append(parts, "技术: "+result.Technique)
	}
	if result.Confidence != "" {
		parts = append(parts, "置信度: "+result.Confidence)
	}
	if result.Summary != "" {
		parts = append(parts, "摘要: "+result.Summary)
	}
	if result.DecodedText != "" {
		parts = append(parts, "恢复文本: "+result.DecodedText)
	}
	if len(result.BenignIndicators) > 0 {
		parts = append(parts, "正常信号: "+strings.Join(result.BenignIndicators, "；"))
	}
	if len(result.RiskIndicators) > 0 {
		parts = append(parts, "风险信号: "+strings.Join(result.RiskIndicators, "；"))
	}
	return strings.Join(parts, "\n")
}

func aggregateEvaluationRisk(details []FindingDetail, blocked bool) string {
	if blocked {
		return "high"
	}
	hasMedium := false
	for _, detail := range details {
		switch detail.Severity {
		case "高风险":
			return "high"
		case "中风险":
			hasMedium = true
		}
	}
	if hasMedium {
		return "medium"
	}
	return "low"
}

func (e *Evaluator) executeRule(ctx context.Context, skill *Skill, rule config.Rule) (score float64, blocked bool, reason string, details []FindingDetail) {
	switch rule.Detection.Type {
	case "pattern":
		// pattern 类型已经在 EvaluateWithCascade 中单独处理，这里不会调用到
		return rule.Weight, false, "", nil
	case "semantic":
		// 语义检测，目前不返回位置
		if e.embedder == nil {
			return rule.Weight, false, "", nil
		}
		codeSummary := extractCodeSummaryFromFiles(skill.Files)
		vectors, err := e.embedder.BatchEmbed([]string{skill.Description, codeSummary})
		if err != nil {
			return rule.Weight, false, "", nil
		}
		sim := similarity.CosineSimilarity(vectors[0], vectors[1])
		if sim < rule.Detection.ThresholdLow {
			if rule.OnFail.Action == "block" {
				return 0, true, rule.OnFail.Reason, nil
			}
			return 0, false, "", nil
		} else if sim < rule.Detection.ThresholdHigh {
			return rule.Weight / 2, false, "", nil
		}
		return rule.Weight, false, "", nil
	case "function":
		fn, ok := e.funcMap[rule.Detection.Function]
		if !ok {
			return rule.Weight, false, "", nil
		}
		// 调用新的签名
		return fn(skill, rule)
	default:
		return rule.Weight, false, "", nil
	}
}

func buildRuleLookup(rules []config.Rule) map[string]config.Rule {
	out := make(map[string]config.Rule, len(rules))
	for _, rule := range rules {
		out[rule.ID] = rule
	}
	return out
}

func mapLLMRiskToRuleID(risk llm.RiskItem, rules map[string]config.Rule) (string, bool) {
	text := strings.ToLower(strings.TrimSpace(risk.Title + " " + risk.Description + " " + risk.Evidence))
	if isLicenseConfigRisk(text) {
		if _, exists := rules["V7-005"]; exists {
			return "V7-005", true
		}
		return "", false
	}
	if isCryptoPolicyRisk(text) {
		if _, exists := rules["V7-003"]; exists {
			return "V7-003", true
		}
		return "", false
	}
	for id, rule := range rules {
		name := strings.ToLower(strings.TrimSpace(rule.Name))
		if name != "" && strings.Contains(text, name) {
			return id, true
		}
	}
	candidates := []struct {
		id       string
		keywords []string
	}{
		{"V7-001", []string{"malicious", "恶意代码", "ransom", "miner", "反弹 shell", "reverse shell", "rm -rf", "c2", "beacon"}},
		{"V7-002", []string{"backdoor", "后门", "条件触发", "隐藏触发"}},
		{"V7-003", []string{"exfiltration", "外发", "隐蔽通道", "dns tunnel", "敏感数据外传", "威胁情报"}},
		{"V7-004", []string{"credential", "password", "secret", "token", "api key", "apikey", "private key", "密钥", "凭证", "令牌"}},
		{"V7-006", []string{"意图", "声明", "不一致", "deception", "intent"}},
		{"V7-007", []string{"mcp", "tool abuse", "工具滥用", "工具权限"}},
		{"V7-008", []string{"sandbox", "沙箱", "escape", "提权", "privilege", "setuid", "capset", "反虚拟机"}},
		{"V7-009", []string{"auto update", "self update", "download exec", "自更新", "下载执行"}},
		{"V7-010", []string{"dependency", "依赖", "malicious package", "漏洞", "cve"}},
		{"V7-011", []string{"prompt injection", "指令注入", "动态指令", "可执行上下文", "注入"}},
		{"V7-013", []string{"path traversal", "路径遍历", "../", "文件越权"}},
		{"V7-014", []string{"ssrf", "内网探测", "169.254", "metadata"}},
		{"V7-015", []string{"tool response", "工具响应", "poison", "投毒"}},
		{"V7-016", []string{"credential cache", "凭据缓存", "跨任务"}},
		{"V7-017", []string{"context leak", "上下文泄露", "敏感上下文", "错误信息泄露"}},
		{"V7-019", []string{"irreversible", "不可逆", "审批", "二次确认"}},
		{"V7-020", []string{"schema", "输入校验", "参数校验"}},
		{"V7-023", []string{"tls", "ssl", "证书", "insecureskipverify", "verify false", "http明文"}},
		{"V7-024", []string{"file upload", "文件上传", "文件解析", "zip slip"}},
		{"V7-026", []string{"resource", "资源耗尽", "dos", "拒绝服务"}},
		{"V7-027", []string{"memory", "记忆", "上下文污染"}},
		{"V7-028", []string{"pickle", "torch.load", "模型文件", "deserialize", "反序列化"}},
		{"V7-029", []string{"hidden", "隐藏", "base64", "混淆"}},
		{"V7-030", []string{"debug", "调试", "测试后门"}},
	}
	for _, candidate := range candidates {
		if _, exists := rules[candidate.id]; !exists {
			continue
		}
		for _, keyword := range candidate.keywords {
			if strings.Contains(text, strings.ToLower(keyword)) {
				return candidate.id, true
			}
		}
	}
	return "", false
}

func normalizeLLMRisk(risk llm.RiskItem) llm.RiskItem {
	text := strings.ToLower(strings.TrimSpace(risk.Title + " " + risk.Description + " " + risk.Evidence))
	if isLicenseConfigRisk(text) {
		risk.Title = "许可证验证配置缺陷"
	}
	if isCryptoPolicyRisk(text) {
		risk.Title = "公司策略禁止的加密资产或预测市场目标"
		risk.Description = normalizeCryptoPolicyDescription(risk.Description)
	}
	return risk
}

func isLicenseConfigRisk(text string) bool {
	if !(strings.Contains(text, "license") || strings.Contains(text, "许可证")) {
		return false
	}
	if isOpenSourceLicenseNoticeText(text) {
		return false
	}
	hasLicenseValidationContext := containsAny(text,
		"verify", "validate", "activation", "activate", "entitlement", "subscription",
		"校验", "验证", "激活", "授权", "订阅",
	)
	hasConfigOrBypassSignal := containsAny(text,
		"localhost", "127.0.0.1", "http://", "license_server", "license server", "endpoint", "server", "url", "env", "mock",
		"验证失败", "fail open", "fail_open", "bypass", "绕过", "skip", "continue", "ignore",
	)
	return hasLicenseValidationContext && hasConfigOrBypassSignal
}

func isOpenSourceLicenseNoticeText(text string) bool {
	if text == "" {
		return false
	}
	if !containsAny(text, "mit license", "apache license", "bsd license", "mpl-2.0", "mozilla public license", "spdx", "copyright") {
		return false
	}
	return !containsAny(text,
		"verify", "validate", "activation", "activate", "entitlement", "subscription",
		"校验", "验证", "激活", "授权", "订阅", "localhost", "127.0.0.1", "bypass", "绕过",
	)
}

func isLicenseConfigCandidateLine(path, line string) bool {
	if isLowSignalExamplePath(path) {
		return false
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || isCommentLikeLine(trimmed) {
		return false
	}
	lower := strings.ToLower(trimmed)
	if isOpenSourceLicenseNoticeText(lower) {
		return false
	}
	if !containsAny(lower, "license", "licence", "许可证", "授权") {
		return false
	}
	return containsAny(lower,
		"verify", "validate", "activation", "activate", "entitlement", "subscription",
		"校验", "验证", "激活", "订阅",
		"localhost", "127.0.0.1", "http://", "license_server", "license server", "endpoint", "server", "url", "env", "mock",
		"验证失败", "fail open", "fail_open", "bypass", "绕过", "skip", "continue", "ignore",
	)
}

func isCryptoPolicyRisk(text string) bool {
	return containsAny(text,
		"polymarket", "clob", "usdc", "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
		"erc-20", "erc20", "crypto asset", "prediction market", "加密资产", "预测市场",
	)
}

func normalizeCryptoPolicyDescription(description string) string {
	description = strings.TrimSpace(description)
	base := "检测到公司技能仓库不应连接的加密资产或预测市场相关目标；若代码仅执行 balanceOf(...).call()、decimals().call() 等链上只读查询，不应表述为破坏性恶意执行，但仍需按准入策略阻断或复核。"
	if description == "" {
		return base
	}
	if strings.Contains(description, "破坏性") || strings.Contains(strings.ToLower(description), "malware") || strings.Contains(description, "恶意资产操作") {
		return base + " 原始 LLM 说明: " + description
	}
	return description
}

func (e *Evaluator) runStaticAnalysis(skill *Skill) *analyzer.CodeAnalysisResult {
	result := &analyzer.CodeAnalysisResult{}
	for _, file := range skill.Files {
		var fileResult *analyzer.CodeAnalysisResult
		switch file.Language {
		case "go":
			fileResult = analyzer.AnalyzeGoCode(file.AnalysisContent(), file.Path)
		case "javascript", "typescript":
			fileResult = analyzer.AnalyzeJavaScriptCode(file.AnalysisContent(), file.Path)
		}
		if fileResult != nil {
			result.DangerousCalls = append(result.DangerousCalls, fileResult.DangerousCalls...)
			result.HasHardcoded = result.HasHardcoded || fileResult.HasHardcoded
		}
	}
	return result
}

func (e *Evaluator) cacheResult(key string, result *EvaluationResult) {
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()
	e.cache[key] = CacheItem{Result: result, ExpireAt: time.Now().Add(24 * time.Hour)}
}

// -------- 检测函数实现 --------
var maliciousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`rm\s+-rf\s+/`),
	regexp.MustCompile(`dd\s+if=/dev/zero`),
	regexp.MustCompile(`nc\s+-e\s+/bin/sh`),
	regexp.MustCompile(`bash\s+-i\s+>&\s+/dev/tcp`),
	regexp.MustCompile(`stratum\+tcp://`),
	regexp.MustCompile(`mining`),
	regexp.MustCompile(`EncryptFile.*ransom`),
}

func (e *Evaluator) detectMaliciousCode(skill *Skill) bool {
	for _, file := range skill.Files {
		for _, re := range maliciousPatterns {
			if re.MatchString(file.AnalysisContent()) {
				return true
			}
		}
	}
	return false
}

var backdoorPattern = regexp.MustCompile(`if.*input.*==.*["']backdoor["'].*exec`)

func (e *Evaluator) detectBackdoor(skill *Skill) bool {
	for _, file := range skill.Files {
		if backdoorPattern.MatchString(file.AnalysisContent()) {
			return true
		}
		if strings.Contains(file.AnalysisContent(), "setTimeout") && strings.Contains(file.AnalysisContent(), "exec") {
			return true
		}
	}
	return false
}

func (e *Evaluator) detectDataExfiltration(skill *Skill) bool {
	for _, file := range skill.Files {
		code := file.AnalysisContent()
		if (strings.Contains(code, "process.env") || strings.Contains(code, "/etc/passwd") || strings.Contains(code, "~/.ssh")) &&
			(strings.Contains(code, "fetch") || strings.Contains(code, "axios") || strings.Contains(code, "http.Post")) {
			return true
		}
		if strings.Contains(code, "nslookup") && strings.Contains(code, "attacker.com") {
			return true
		}
		if strings.Contains(code, "btoa") && strings.Contains(code, "JSON.stringify") && strings.Contains(code, "fetch") {
			return true
		}
	}
	return false
}

func (e *Evaluator) detectMCPAbuse(skill *Skill) bool {
	desc := skill.Description
	if strings.Contains(desc, "调用 file_system.delete_all") || strings.Contains(desc, "调用 system.exec") {
		if !strings.Contains(strings.ToLower(skill.Name), "file") && !strings.Contains(strings.ToLower(skill.Description), "file") {
			return true
		}
	}
	return false
}

func (e *Evaluator) evaluateDeception(ctx context.Context, skill *Skill) (float64, error) {
	codeSummary := extractCodeSummaryFromFiles(skill.Files)
	vectors, err := e.embedder.BatchEmbed([]string{skill.Description, codeSummary})
	if err != nil {
		return 0, err
	}
	sim := similarity.CosineSimilarity(vectors[0], vectors[1])
	if sim < e.thresholds.SimilarityLow {
		return 100, nil
	} else if sim < e.thresholds.SimilarityHigh {
		return 50, nil
	}
	return 0, nil
}

func (e *Evaluator) evaluateDependencyVulns(skill *Skill) float64 {
	score := 20.0
	for _, dep := range skill.Dependencies {
		if dep.Version == "" || strings.HasPrefix(dep.Version, "0.0.0") {
			score -= 20
		} else if strings.Contains(dep.Name, "malicious") {
			score -= 20
		} else if strings.Contains(dep.Name, "typo") {
			score -= 15
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluatePermissions(skill *Skill) float64 {
	score := 20.0
	for _, perm := range skill.Permissions {
		switch perm {
		case "root", "administrator":
			score -= 20
		case "/**":
			score -= 15
		case "0.0.0.0":
			score -= 10
		case "HOME", "PATH":
			score -= 5
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluateInjectionRisk(skill *Skill) float64 {
	score := 15.0
	for _, file := range skill.Files {
		if isLowSignalExamplePath(file.Path) {
			continue
		}
		code := file.AnalysisContent()
		if hasPromptOverrideIntent(code) || decodedPromptOverrideIntent(code) {
			score -= 15
			break
		}
		if strings.Contains(code, "exec.Command") && strings.Contains(code, "input") {
			score -= 15
			break
		}
		if strings.Contains(code, "llm.Output") && strings.Contains(code, "exec") {
			score -= 12
			break
		}
		if strings.Contains(code, "args") && !strings.Contains(code, "whitelist") {
			score -= 8
			break
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluateContextLeak(skill *Skill) float64 {
	score := 10.0
	for _, file := range skill.Files {
		code := file.AnalysisContent()
		// 原有模式
		if strings.Contains(code, "system_prompt") && strings.Contains(code, "return") {
			score -= 10
			break
		}
		if strings.Contains(code, "config") && strings.Contains(code, "error") {
			score -= 8
			break
		}
		if strings.Contains(code, "log") && strings.Contains(code, "secret") {
			score -= 5
			break
		}
		// 新增模式：日志中输出敏感变量
		if strings.Contains(code, "log.") && (strings.Contains(code, "password") || strings.Contains(code, "token") || strings.Contains(code, "key")) {
			score -= 6
			break
		}
		// 新增模式：错误信息中返回敏感数据
		if strings.Contains(code, "fmt.Errorf") && strings.Contains(code, "%v") && (strings.Contains(code, "secret") || strings.Contains(code, "password")) {
			score -= 7
			break
		}
		// 新增模式：将敏感信息拼接到 HTTP 响应
		if strings.Contains(code, "http.") && strings.Contains(code, "Write") && (strings.Contains(code, "password") || strings.Contains(code, "token")) {
			score -= 8
			break
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluateSoftDependencies(skill *Skill) float64 {
	score := 10.0
	for _, file := range skill.Files {
		code := file.AnalysisContent()
		if strings.Contains(code, "http.Get") && strings.Contains(code, ".js") && !strings.Contains(code, "hash") {
			score -= 10
			break
		}
		if strings.Contains(code, "http.Get") && !strings.Contains(code, "https://") {
			score -= 5
			break
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluateCredentialIsolation(skill *Skill) float64 {
	score := 10.0
	for _, file := range skill.Files {
		lines := strings.Split(file.AnalysisContent(), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isCommentLikeLine(trimmed) {
				continue
			}
			if isLikelyLogOnlyLine(trimmed) {
				continue
			}
			lower := strings.ToLower(trimmed)
			if strings.Contains(lower, "global.credential") || strings.Contains(lower, "global_credentials") {
				score -= 10
				break
			}
			if strings.Contains(lower, "session") && strings.Contains(lower, "credential") && (strings.Contains(lower, "=") || strings.Contains(lower, "set") || strings.Contains(lower, "cache") || strings.Contains(lower, "store")) {
				score -= 8
				break
			}
			if strings.Contains(lower, "credential") && (strings.Contains(lower, "cache") || strings.Contains(lower, "persist") || strings.Contains(lower, "redis") || strings.Contains(lower, "memcached")) {
				score -= 6
				break
			}
		}
		if score < 10 {
			break
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluateHiddenContent(skill *Skill) float64 {
	score := 5.0
	base64Count := 0
	highEntropyFound := false
	llmBenignBias := false
	llmRiskBias := false
	for _, file := range skill.Files {
		if isLowSignalExamplePath(file.Path) {
			continue
		}
		code := file.AnalysisContent()
		if strings.Contains(code, "\u202E") || containsZeroWidthOrBidiControl(code) {
			score -= 5
			break
		}
		if hasPromptOverrideIntent(code) || decodedPromptOverrideIntent(code) {
			score -= 4
		}
		if strings.Contains(code, "btoa") {
			base64Count++
		}
		if strings.Contains(code, "atob") {
			base64Count++
		}
		if !highEntropyFound && analyzer.CalculateEntropy(code) > 5.0 {
			highEntropyFound = true
		}
		if e.llmClient != nil && ShouldUseLLMForObfuscation(file.Content, file.PreprocessedContent) {
			analysis, err := e.llmClient.AnalyzeObfuscatedContent(context.Background(), filepath.Base(file.Path), trimObfuscationInput(file.Content, file.PreprocessedContent))
			if err == nil && analysis != nil {
				if len(analysis.BenignIndicators) > len(analysis.RiskIndicators) {
					llmBenignBias = true
				}
				if analysis.LikelyObfuscated && len(analysis.RiskIndicators) > 0 {
					llmRiskBias = true
				}
			}
		}
	}
	if base64Count >= 2 {
		score -= 3
	}
	if highEntropyFound {
		score -= 2
	}
	if llmBenignBias && score < 5 {
		score += 1
	}
	if llmRiskBias {
		score -= 1
	}
	if score < 0 {
		score = 0
	}
	if score > 5 {
		score = 5
	}
	return score
}

func (e *Evaluator) evaluateResourceRisk(skill *Skill) float64 {
	score := 5.0
	loopRe := regexp.MustCompile(`(?i)^for\s*\{\s*$|^while\s*\(?\s*true\s*\)?\s*[:{]?$|for\s*\(\s*;\s*;\s*\)`)
	for _, file := range skill.Files {
		lines := strings.Split(file.AnalysisContent(), "\n")
		hasHTTPGet := false
		hasTimeout := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isCommentLikeLine(trimmed) {
				continue
			}
			lower := strings.ToLower(trimmed)
			if loopRe.MatchString(trimmed) {
				score -= 5
				break
			}
			if strings.Contains(lower, "http.get(") || strings.Contains(lower, "requests.get(") {
				hasHTTPGet = true
			}
			if strings.Contains(lower, "timeout") || strings.Contains(lower, "context.withtimeout") || strings.Contains(lower, "client.timeout") {
				hasTimeout = true
			}
		}
		if score < 5 {
			break
		}
		if hasHTTPGet && !hasTimeout {
			score -= 2
			break
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluateMemoryIsolation(skill *Skill) float64 {
	score := 5.0
	for _, file := range skill.Files {
		code := file.AnalysisContent()
		if strings.Contains(code, "memory.write") && strings.Contains(code, "input") {
			score -= 5
			break
		}
		if strings.Contains(code, "memory.read") && !strings.Contains(code, "permission") {
			score -= 3
			break
		}
		if strings.Contains(code, "memory.share") {
			score -= 5
			break
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

// -------- 辅助函数 --------
func extractCodeSummary(code string) string {
	var summary strings.Builder
	functions := extractFunctionSignatures(code)
	for _, f := range functions {
		summary.WriteString(f.Name + " ")
	}
	imports := extractImports(code)
	for _, imp := range imports {
		summary.WriteString(imp + " ")
	}
	comments := extractComments(code)
	for _, c := range comments {
		if len(c) > 10 {
			summary.WriteString(c + " ")
		}
	}
	strings := extractStringLiterals(code)
	for _, s := range strings {
		if len(s) > 5 && len(s) < 50 {
			summary.WriteString(s + " ")
		}
	}
	return summary.String()
}

func extractCodeSummaryFromFiles(files []SourceFile) string {
	var summary strings.Builder
	for _, file := range files {
		summary.WriteString(extractCodeSummary(file.AnalysisContent()))
		summary.WriteString(" ")
	}
	return summary.String()
}

func extractFunctionSignatures(code string) []struct{ Name string } {
	var res []struct{ Name string }
	lines := strings.Split(code, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "func ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				res = append(res, struct{ Name string }{Name: parts[1]})
			}
		}
	}
	return res
}

func extractImports(code string) []string {
	var res []string
	lines := strings.Split(code, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "import ") {
			parts := strings.Fields(line)
			for _, p := range parts[1:] {
				if strings.HasPrefix(p, `"`) {
					res = append(res, strings.Trim(p, `"`))
				}
			}
		}
	}
	return res
}

func extractComments(code string) []string {
	var res []string
	lines := strings.Split(code, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			res = append(res, strings.TrimSpace(strings.TrimPrefix(line, "//")))
		}
	}
	return res
}

func extractStringLiterals(code string) []string {
	var res []string
	re := regexp.MustCompile(`"([^"\\]|\\.)*"`)
	matches := re.FindAllString(code, -1)
	for _, m := range matches {
		res = append(res, strings.Trim(m, `"`))
	}
	return res
}

func formatCodeContext(lines []string, centerLine int, radius int) string {
	start := centerLine - radius
	if start < 0 {
		start = 0
	}
	end := centerLine + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	var builder strings.Builder
	for i := start; i < end; i++ {
		prefix := "  "
		if i == centerLine {
			prefix = "> "
		}
		builder.WriteString(fmt.Sprintf("%s%4d | %s\n", prefix, i+1, lines[i]))
	}
	return builder.String()
}

// -------- 包装函数 --------
func (e *Evaluator) detectHardcodedCredentialFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	var details []FindingDetail
	// 遍历所有文件查找硬编码凭证
	credPatterns := []string{
		`(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']+["']`,
		`(?i)(api[_-]?key|apikey|secret|token)\s*[:=]\s*["'][^"']+["']`,
		`(?i)(private[_-]?key|privkey)\s*[:=]\s*["'][^"']+["']`,
	}
	for _, file := range skill.Files {
		lines := strings.Split(file.Content, "\n")
		for i, line := range lines {
			for _, pat := range credPatterns {
				if matched, _ := regexp.MatchString(pat, line); matched {
					// ⭐ 新增排除逻辑：如果是空字符串或明显占位符则跳过，避免误报
					lowerLine := strings.ToLower(line)
					if strings.Contains(lowerLine, `""`) || strings.Contains(lowerLine, `''`) ||
						strings.Contains(lowerLine, `"your_`) || strings.Contains(lowerLine, `"example`) ||
						strings.Contains(lowerLine, `"test`) || strings.Contains(lowerLine, `"xxx`) ||
						strings.Contains(lowerLine, `"0xYOUR`) {
						continue // 跳过这条匹配，不生成告警
					}

					// 找到硬编码凭证
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "高风险",
						Title:       rule.Name,
						Description: rule.OnFail.Reason,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					break // 一行只记录一次
				}
			}
		}
	}
	if len(details) > 0 {
		if rule.OnFail.Action == "block" {
			return 0, true, rule.OnFail.Reason, details
		}
		return 0, false, "", details
	}
	return rule.Weight, false, "", nil
}

func (e *Evaluator) detectDataExfiltrationFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	var details []FindingDetail
	patterns := []struct {
		pattern string
		desc    string
	}{
		{`(process\.env|/etc/passwd|~/.ssh).*(fetch|axios|http\.Post)`, "读取敏感文件并通过网络发送"},
		{`nslookup.*attacker\.com`, "DNS外带数据"},
		{`btoa.*JSON\.stringify.*fetch`, "Base64编码数据后外发"},
		{`(?i)(clob\.polymarket\.com|polymarket\.com|0x2791bca1f2de4661ed88a30c99a7a9449aa84174|\bUSDC\b|\bERC-?20\b)`, "检测到公司技能仓库准入策略禁止的加密资产或预测市场相关目标；如仅为链上只读查询，不归类为破坏性恶意执行，但仍需阻断或复核"},
	}
	for _, file := range skill.Files {
		lines := strings.Split(file.Content, "\n")
		for i, line := range lines {
			for _, p := range patterns {
				if matched, _ := regexp.MatchString(p.pattern, line); matched {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "高风险",
						Title:       rule.Name,
						Description: rule.OnFail.Reason + ": " + p.desc,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					break
				}
			}
		}
	}
	if len(details) > 0 {
		if rule.OnFail.Action == "block" {
			return 0, true, rule.OnFail.Reason, details
		}
		return 0, false, "", details
	}
	return rule.Weight, false, "", nil
}

func (e *Evaluator) detectMCPAbuseFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	var details []FindingDetail
	// 检测描述中的滥用
	if strings.Contains(skill.Description, "调用 file_system.delete_all") ||
		strings.Contains(skill.Description, "调用 system.exec") {
		if !strings.Contains(strings.ToLower(skill.Name), "file") &&
			!strings.Contains(strings.ToLower(skill.Description), "file") {
			detail := FindingDetail{
				RuleID:      rule.ID,
				Severity:    "高风险",
				Title:       rule.Name,
				Description: rule.OnFail.Reason,
				Location:    "技能描述",
				CodeSnippet: skill.Description,
			}
			details = append(details, detail)
		}
	}
	// 检测代码中是否包含MCP相关调用（示例）
	for _, file := range skill.Files {
		if strings.Contains(file.AnalysisContent(), "mcp__") || strings.Contains(file.AnalysisContent(), "call_tool") {
			lines := strings.Split(file.AnalysisContent(), "\n")
			for i, line := range lines {
				if strings.Contains(line, "delete_all") || strings.Contains(line, "system.exec") {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "高风险",
						Title:       rule.Name,
						Description: rule.OnFail.Reason,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					break
				}
			}
		}
	}
	if len(details) > 0 {
		if rule.OnFail.Action == "block" {
			return 0, true, rule.OnFail.Reason, details
		}
		return 0, false, "", details
	}
	return rule.Weight, false, "", nil
}

func (e *Evaluator) detectEnvironmentEvasionFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	var details []FindingDetail
	patterns := []struct {
		re   *regexp.Regexp
		desc string
	}{
		{regexp.MustCompile(`(?i)\.dockerenv|/proc/1/cgroup|docker`), "检测容器环境特征"},
		{regexp.MustCompile(`(?i)systemd-detect-virt|dmidecode|hypervisor|qemu|vbox|vmware`), "检测虚拟机环境特征"},
		{regexp.MustCompile(`(?i)isdebuggerpresent|ptrace|cpuid|rdtsc`), "检测调试或分析环境"},
		{regexp.MustCompile(`(?i)\b(unshare|capset|setuid|setgid|mount)\b|/proc/self/ns`), "检测命名空间、挂载或提权相关能力"},
		{regexp.MustCompile(`(?i)sleep\((3\d{2}|[6-9]\d{2,})\)|time\.sleep\((3\d{2}|[6-9]\d{2,})\)`), "检测异常长延时反分析逻辑"},
	}

	for _, file := range skill.Files {
		lines := strings.Split(file.AnalysisContent(), "\n")
		for i, line := range lines {
			for _, p := range patterns {
				if p.re.MatchString(line) {
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    "高风险",
						Title:       rule.Name,
						Description: rule.OnFail.Reason + "：" + p.desc,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
					break
				}
			}
		}
	}

	if len(details) == 0 {
		return rule.Weight, false, "", nil
	}
	if rule.OnFail.Action == "block" {
		return 0, true, rule.OnFail.Reason, details
	}
	return 0, false, "", details
}

func (e *Evaluator) evaluateIrreversibleOpsApprovalFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	type opCandidate struct {
		Label      string
		Category   string
		Location   string
		Snippet    string
		Confidence int
		HasScope   bool
	}

	actionPatterns := []struct {
		Label      string
		Category   string
		Confidence int
		Regex      *regexp.Regexp
	}{
		{Label: "数据删除", Category: "destructive", Confidence: 2, Regex: regexp.MustCompile(`(?i)\b(os\.remove|os\.unlink|shutil\.rmtree|rm\s+-rf|delete\s+from|drop\s+table|truncate\s+table|delete\()`)},
		{Label: "支付转账", Category: "payment", Confidence: 2, Regex: regexp.MustCompile(`(?i)\b(payment|transfer|charge|refund|pay\()`)},
		{Label: "通知发送", Category: "notification", Confidence: 1, Regex: regexp.MustCompile(`(?i)\b(send_email|send_sms|send_notification|sendEmail|sendSMS|sendNotification|push_notification|notify\()`)},
		{Label: "中文不可逆动作", Category: "destructive", Confidence: 2, Regex: regexp.MustCompile(`(删除|支付|转账|发送通知)`)},
	}

	scopeRegex := regexp.MustCompile(`(?i)(user|account|order|payment|invoice|balance|credential|session|token|database|table|file|record|message|用户|订单|账号|账户|支付|数据库|文件|记录|消息)`)
	approvalMarkers := []string{
		"human-in-the-loop", "manual approval", "approval", "confirm", "confirmation", "two-step",
		"人工确认", "人工审批", "二次确认", "确认后", "审批后", "需人工",
	}

	candidates := make([]opCandidate, 0)
	ops := make([]string, 0)
	descLower := strings.ToLower(skill.Description)
	hasDescScope := scopeRegex.MatchString(descLower)

	for _, file := range skill.Files {
		lines := strings.Split(file.Content, "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isCommentLikeLine(trimmed) {
				continue
			}
			if isLikelyLogOnlyLine(trimmed) {
				continue
			}
			lower := strings.ToLower(trimmed)
			for _, p := range actionPatterns {
				if p.Regex.MatchString(lower) {
					ops = append(ops, p.Label)
					candidates = append(candidates, opCandidate{
						Label:      p.Label,
						Category:   p.Category,
						Location:   fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						Snippet:    formatCodeContext(lines, i, 1),
						Confidence: p.Confidence,
						HasScope:   scopeRegex.MatchString(lower) || hasDescScope,
					})
				}
			}
		}
	}
	ops = uniqueStrings(ops)

	effective := make([]opCandidate, 0)
	for _, c := range candidates {
		if c.Confidence >= 2 {
			effective = append(effective, c)
			continue
		}
		if c.Confidence == 1 && c.HasScope {
			effective = append(effective, c)
		}
	}

	if len(effective) == 0 {
		return rule.Weight, false, "", nil
	}

	hasApproval := false
	for _, marker := range approvalMarkers {
		if strings.Contains(strings.ToLower(skill.Description), strings.ToLower(marker)) {
			hasApproval = true
			break
		}
	}
	if !hasApproval {
		for _, file := range skill.Files {
			lines := strings.Split(file.AnalysisContent(), "\n")
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || isCommentLikeLine(trimmed) {
					continue
				}
				lower := strings.ToLower(trimmed)
				for _, marker := range approvalMarkers {
					if strings.Contains(lower, strings.ToLower(marker)) {
						hasApproval = true
						break
					}
				}
				if hasApproval {
					break
				}
			}
			if hasApproval {
				break
			}
		}
	}

	if hasApproval {
		return rule.Weight, false, "", nil
	}

	preview := make([]string, 0, 3)
	locSet := make(map[string]struct{})
	for i, c := range effective {
		if i < 3 {
			preview = append(preview, fmt.Sprintf("[%s] %s", c.Label, c.Location))
		}
		locSet[c.Location] = struct{}{}
	}
	locs := make([]string, 0, len(locSet))
	for loc := range locSet {
		locs = append(locs, loc)
	}

	impactSummary := "未识别到明确影响范围"
	for _, c := range effective {
		if c.HasScope {
			impactSummary = "识别到用户/订单/账户等影响范围"
			break
		}
	}

	snippet := strings.Builder{}
	for i, c := range effective {
		if i >= 2 {
			break
		}
		snippet.WriteString(fmt.Sprintf("命中动作: %s\n位置: %s\n%s\n", c.Label, c.Location, c.Snippet))
	}

	detail := FindingDetail{
		RuleID:      rule.ID,
		Severity:    "高风险",
		Title:       rule.Name,
		Description: fmt.Sprintf("检测到不可逆操作候选（%s）；动作语义判定命中（%s）；数据影响范围判定：%s；但未发现人工确认或审批步骤。", strings.Join(ops, "、"), strings.Join(preview, "；"), impactSummary),
		Location:    defaultEvidenceLocation(strings.Join(locs, "；")),
		CodeSnippet: defaultEvidenceSnippet(snippet.String()),
	}

	if rule.OnFail.NoCompensationBlock {
		return 0, true, rule.OnFail.Reason, []FindingDetail{detail}
	}
	return 0, false, "", []FindingDetail{detail}
}

func (e *Evaluator) evaluateDataMinimizationEvidenceFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	declared, declaredEvidence := collectSensitiveSignals(skill.Description, "技能声明", false)
	actual := make([]string, 0)
	actualEvidenceByLabel := make(map[string]signalEvidence)
	for _, file := range skill.Files {
		labels, evidences := collectSensitiveSignals(file.AnalysisContent(), filepath.Base(file.Path), true)
		actual = append(actual, labels...)
		for _, ev := range evidences {
			if _, ok := actualEvidenceByLabel[ev.Label]; !ok {
				actualEvidenceByLabel[ev.Label] = ev
			}
		}
	}
	actual = uniqueStrings(actual)

	if len(declared) == 0 && len(actual) == 0 {
		return rule.Weight, false, "", nil
	}

	extra := diffStrings(actual, declared)
	desc := fmt.Sprintf("技能声明收集的数据：%s\n技能实际收集的数据：%s", joinOrFallback(declared), joinOrFallback(actual))
	severity := "低风险"
	score := rule.Weight
	if len(extra) > 0 {
		severity = "中风险"
		desc += fmt.Sprintf("\n检测到声明外数据收集：%s", strings.Join(extra, "、"))
		score = rule.Weight * 0.4
	}

	summarySnippet := fmt.Sprintf(
		"声明收集数据: %s\n实际收集数据: %s\n声明外收集: %s\n声明证据: %s\n行为证据: %s",
		joinOrFallback(declared),
		joinOrFallback(actual),
		joinOrFallback(extra),
		joinOrFallback(formatSignalEvidence(declaredEvidence)),
		joinOrFallback(formatSignalEvidenceMap(actualEvidenceByLabel, actual)),
	)

	details := []FindingDetail{{
		RuleID:      rule.ID,
		Severity:    severity,
		Title:       rule.Name,
		Description: desc,
		Location:    "技能声明与数据收集行为对照",
		CodeSnippet: summarySnippet,
	}}

	if len(extra) > 0 {
		for _, label := range extra {
			ev, ok := actualEvidenceByLabel[label]
			if !ok {
				continue
			}
			details = append(details, FindingDetail{
				RuleID:      rule.ID,
				Severity:    "中风险",
				Title:       rule.Name,
				Description: fmt.Sprintf("检测到声明外数据收集类型：%s", label),
				Location:    defaultEvidenceLocation(ev.Location),
				CodeSnippet: fmt.Sprintf("命中数据类型: %s\n关键证据:\n%s", label, defaultEvidenceSnippet(ev.Snippet)),
			})
		}
		return score, false, "", details
	}
	return rule.Weight, false, "", details
}

type signalEvidence struct {
	Label    string
	Location string
	Snippet  string
}

var sensitiveSignalPatterns = map[string][]string{
	"姓名":   {"name", "full_name", "姓名"},
	"手机号":  {"phone", "mobile", "手机号", "电话"},
	"邮箱":   {"email", "邮箱"},
	"身份证号": {"id_card", "identity", "身份证"},
	"地址":   {"address", "地址"},
	"地理位置": {"location", "geo", "gps", "地理位置"},
	"设备标识": {"device_id", "imei", "mac", "设备标识"},
	"银行卡":  {"bank_card", "card_no", "银行卡"},
	"订单信息": {"order", "订单"},
	"会话标识": {"session", "cookie", "token", "会话"},
}

func collectSensitiveSignals(text, source string, lineMode bool) ([]string, []signalEvidence) {
	labels := make([]string, 0)
	evidences := make([]signalEvidence, 0)
	textLower := strings.ToLower(text)
	lines := strings.Split(text, "\n")

	for label, keys := range sensitiveSignalPatterns {
		matched := false
		for _, key := range keys {
			k := strings.ToLower(key)
			if !strings.Contains(textLower, k) {
				continue
			}
			labels = append(labels, label)
			matched = true

			location := source
			snippet := ""
			if lineMode {
				for i, line := range lines {
					if strings.Contains(strings.ToLower(line), k) {
						location = fmt.Sprintf("%s:%d", source, i+1)
						snippet = formatCodeContext(lines, i, 1)
						break
					}
				}
			} else {
				snippet = strings.TrimSpace(text)
				if len(snippet) > 200 {
					snippet = snippet[:200] + "..."
				}
			}

			evidences = append(evidences, signalEvidence{
				Label:    label,
				Location: location,
				Snippet:  snippet,
			})
			break
		}
		if matched {
			continue
		}
	}

	return uniqueStrings(labels), uniqueSignalEvidence(evidences)
}

func uniqueSignalEvidence(items []signalEvidence) []signalEvidence {
	seen := make(map[string]struct{}, len(items))
	out := make([]signalEvidence, 0, len(items))
	for _, item := range items {
		key := item.Label + "|" + item.Location
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func formatSignalEvidence(items []signalEvidence) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		loc := defaultEvidenceLocation(item.Location)
		snippet := defaultEvidenceSnippet(item.Snippet)
		out = append(out, fmt.Sprintf("%s@%s", item.Label, loc))
		if snippet != "未提取到代码或文本片段" {
			out = append(out, fmt.Sprintf("%s证据: %s", item.Label, snippet))
		}
	}
	return uniqueStrings(out)
}

func formatSignalEvidenceMap(m map[string]signalEvidence, labels []string) []string {
	out := make([]string, 0, len(labels))
	for _, label := range labels {
		ev, ok := m[label]
		if !ok {
			continue
		}
		out = append(out, fmt.Sprintf("%s@%s", label, defaultEvidenceLocation(ev.Location)))
	}
	return uniqueStrings(out)
}

func defaultEvidenceLocation(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "未定位"
	}
	return v
}

func defaultEvidenceSnippet(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "未提取到代码或文本片段"
	}
	return v
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		v := strings.TrimSpace(item)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func diffStrings(left, right []string) []string {
	rightSet := make(map[string]struct{}, len(right))
	for _, v := range right {
		rightSet[v] = struct{}{}
	}
	out := make([]string, 0)
	for _, v := range left {
		if _, ok := rightSet[v]; !ok {
			out = append(out, v)
		}
	}
	return uniqueStrings(out)
}

func joinOrFallback(items []string) string {
	if len(items) == 0 {
		return "未声明或未识别"
	}
	return strings.Join(items, "、")
}

func (e *Evaluator) evaluateDependencyVulnsFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluateDependencyVulns(skill)
	var details []FindingDetail
	if score < rule.Weight {
		details = append(details, FindingDetail{
			RuleID:      rule.ID,
			Severity:    "中风险",
			Title:       rule.Name,
			Description: "依赖项存在安全风险。",
			Location:    "请检查 go.mod 或 package.json 中的依赖项",
		})
	}
	return score, false, "", details
}

func (e *Evaluator) evaluatePermissionsFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluatePermissions(skill)
	var details []FindingDetail
	if score < rule.Weight {
		// 列出过度申请的权限
		excessive := []string{}
		for _, perm := range skill.Permissions {
			if perm == "root" || perm == "administrator" || perm == "/**" || perm == "0.0.0.0" {
				excessive = append(excessive, perm)
			}
		}
		detail := FindingDetail{
			RuleID:      rule.ID,
			Severity:    "中风险",
			Title:       rule.Name,
			Description: fmt.Sprintf("申请了过高权限: %s", strings.Join(excessive, ", ")),
			Location:    "用户声明的权限",
			CodeSnippet: strings.Join(skill.Permissions, ", "),
		}
		details = append(details, detail)
	}
	return score, false, "", details
}

func (e *Evaluator) evaluateContextLeakFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := rule.Weight
	var details []FindingDetail

	sensitiveKeys := []string{"password", "token", "secret", "apikey", "api_key", "credential", "authorization", "cookie", "session", "私钥", "密钥", "凭据"}
	sinkKeys := []string{"return", "http.write", "json.newencoder", "responsewriter", "log.", "logger.", "fmt.printf", "fmt.sprintf", "fmt.errorf", "print("}
	maskKeys := []string{"mask", "redact", "sanitize", "omit", "hash", "truncate", "脱敏", "过滤"}
	scopeKeys := []string{"response", "body", "outbound", "upload", "send", "push", "http", "返回"}

	phase1Hit := false
	phase2Protected := false
	phase3Scoped := false

	for _, file := range skill.Files {
		lines := strings.Split(file.AnalysisContent(), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isCommentLikeLine(trimmed) {
				continue
			}
			lower := strings.ToLower(trimmed)
			if containsAny(lower, sensitiveKeys...) && containsAny(lower, sinkKeys...) {
				phase1Hit = true
				if containsAny(lower, scopeKeys...) {
					phase3Scoped = true
				}
				window := joinNearbyLines(lines, i, 1)
				if containsAny(strings.ToLower(window), maskKeys...) {
					phase2Protected = true
				}
				if !phase2Protected {
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    "中风险",
						Title:       rule.Name,
						Description: "三段判定命中：存在敏感信息输出语义，且未识别到脱敏控制。",
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
				}
			}
		}
	}

	if !phase1Hit || (phase1Hit && phase2Protected) {
		return score, false, "", nil
	}

	if phase3Scoped {
		score = rule.Weight * 0.35
	} else {
		score = rule.Weight * 0.6
	}
	return score, false, "", details
}

func (e *Evaluator) evaluateSoftDependenciesFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluateSoftDependencies(skill)
	var details []FindingDetail
	if score < rule.Weight {
		found := false
		for _, file := range skill.Files {
			lines := strings.Split(file.AnalysisContent(), "\n")
			for i, line := range lines {
				if strings.Contains(line, "http.Get") && !strings.Contains(line, "hash") {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "中风险",
						Title:       rule.Name,
						Description: "外部软依赖缺少完整性校验。",
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found && len(skill.Files) > 0 {
			details = append(details, FindingDetail{
				RuleID:      rule.ID,
				Severity:    "中风险",
				Title:       rule.Name,
				Description: "外部软依赖存在安全风险。",
				Location:    filepath.Base(skill.Files[0].Path),
				CodeSnippet: "未定位到具体行，请检查外部资源加载代码。",
			})
		}
	}
	return score, false, "", details
}

func (e *Evaluator) evaluateCredentialIsolationFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := rule.Weight
	var details []FindingDetail

	actionKeys := []string{"credential", "token", "password", "secret"}
	storeKeys := []string{"cache", "store", "persist", "redis", "memcached", "global", "session", "set("}
	protectKeys := []string{"encrypt", "kms", "vault", "ttl", "expire", "rotation", "scope", "user_id", "tenant_id", "加密", "轮换", "过期"}
	scopeKeys := []string{"global", "shared", "cross", "all_user", "all tenant", "跨任务", "跨用户"}

	phase1Hit := false
	phase2Protected := false
	phase3Scoped := false

	for _, file := range skill.Files {
		lines := strings.Split(file.AnalysisContent(), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isCommentLikeLine(trimmed) || isLikelyLogOnlyLine(trimmed) {
				continue
			}
			lower := strings.ToLower(trimmed)
			if containsAny(lower, actionKeys...) && containsAny(lower, storeKeys...) {
				phase1Hit = true
				if containsAny(lower, scopeKeys...) {
					phase3Scoped = true
				}
				window := joinNearbyLines(lines, i, 2)
				if containsAny(strings.ToLower(window), protectKeys...) {
					phase2Protected = true
				}
				if !phase2Protected {
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    "中风险",
						Title:       rule.Name,
						Description: "三段判定命中：凭据存在缓存/持久化语义，未识别到加密与作用域隔离控制。",
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
				}
			}
		}
	}

	if !phase1Hit || (phase1Hit && phase2Protected) {
		return score, false, "", nil
	}
	if phase3Scoped {
		score = rule.Weight * 0.35
	} else {
		score = rule.Weight * 0.6
	}
	return score, false, "", details
}

func (e *Evaluator) evaluateHiddenContentFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluateHiddenContent(skill)
	var details []FindingDetail
	if score < rule.Weight {
		for _, file := range skill.Files {
			if isLowSignalExamplePath(file.Path) {
				continue
			}
			lines := strings.Split(file.Content, "\n")
			for i, line := range lines {
				// 具体检测内容
				if strings.Contains(line, "\u202E") || containsZeroWidthOrBidiControl(line) {
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    "低风险",
						Title:       rule.Name,
						Description: fmt.Sprintf("检测到 Unicode 方向覆盖或零宽控制字符，可能用于隐藏恶意代码或提示词覆盖"),
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
				}
				if hasPromptOverrideIntent(line) || decodedPromptOverrideIntent(line) {
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    "中风险",
						Title:       rule.Name,
						Description: "检测到直接或编码隐藏的提示词覆盖/越权指令，可能诱导模型忽略上层指令或绕过审批。",
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
				}
				if strings.Contains(line, "btoa") {
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    "低风险",
						Title:       rule.Name,
						Description: fmt.Sprintf("使用 btoa 进行 Base64 编码，可能用于混淆数据"),
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
				}
				if strings.Contains(line, "atob") {
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    "低风险",
						Title:       rule.Name,
						Description: fmt.Sprintf("使用 atob 解码 Base64，可能用于隐藏执行"),
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
				}
			}
		}
		// 高熵检测（全文件级别）
		for _, file := range skill.Files {
			if isLowSignalExamplePath(file.Path) {
				continue
			}
			entropy := analyzer.CalculateEntropy(file.AnalysisContent())
			if entropy > 5.0 {
				details = append(details, FindingDetail{
					RuleID:      rule.ID,
					Severity:    "低风险",
					Title:       rule.Name,
					Description: fmt.Sprintf("文件整体熵值过高 (%.2f)，可能包含加密或压缩数据", entropy),
					Location:    filepath.Base(file.Path),
					CodeSnippet: "整个文件熵值异常",
				})
				break
			}
		}
		if e.llmClient != nil {
			for _, file := range skill.Files {
				if isLowSignalExamplePath(file.Path) || !ShouldUseLLMForObfuscation(file.Content, file.PreprocessedContent) {
					continue
				}
				analysis, err := e.llmClient.AnalyzeObfuscatedContent(context.Background(), filepath.Base(file.Path), trimObfuscationInput(file.Content, file.PreprocessedContent))
				if err != nil || analysis == nil || !analysis.LikelyObfuscated {
					continue
				}
				severity := "低风险"
				if len(analysis.RiskIndicators) > len(analysis.BenignIndicators) {
					severity = "中风险"
				}
				details = append(details, FindingDetail{
					RuleID:      rule.ID,
					Severity:    severity,
					Title:       rule.Name,
					Description: defaultText(strings.TrimSpace(analysis.Summary), "LLM 识别到疑似混淆或编码内容，建议结合恢复语义进一步复核。"),
					Location:    filepath.Base(file.Path),
					CodeSnippet: formatLLMObfuscationSnippet(analysis),
				})
				break
			}
		}
	}
	// 如果分数被扣但未生成任何详情（理论上不会，但做兜底）
	if len(details) == 0 && score < rule.Weight && len(skill.Files) > 0 {
		details = append(details, FindingDetail{
			RuleID:      rule.ID,
			Severity:    "低风险",
			Title:       rule.Name,
			Description: "可能存在隐藏内容。",
			Location:    filepath.Base(skill.Files[0].Path),
			CodeSnippet: "未定位到具体行，请检查是否存在混淆代码或高熵数据。",
		})
	}
	return score, false, "", details
}

func (e *Evaluator) evaluateResourceRiskFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluateResourceRisk(skill)
	var details []FindingDetail
	if score < rule.Weight {
		loopRe := regexp.MustCompile(`(?i)^for\s*\{\s*$|^while\s*\(?\s*true\s*\)?\s*[:{]?$|for\s*\(\s*;\s*;\s*\)`)
		found := false
		for _, file := range skill.Files {
			lines := strings.Split(file.AnalysisContent(), "\n")
			hasHTTPGet := false
			hasTimeout := false
			httpLine := -1
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || isCommentLikeLine(trimmed) {
					continue
				}
				lower := strings.ToLower(trimmed)
				if loopRe.MatchString(trimmed) {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "低风险",
						Title:       rule.Name,
						Description: "检测到无退出条件循环，存在资源耗尽风险。",
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					found = true
					break
				}
				if strings.Contains(lower, "http.get(") || strings.Contains(lower, "requests.get(") {
					hasHTTPGet = true
					httpLine = i
				}
				if strings.Contains(lower, "timeout") || strings.Contains(lower, "context.withtimeout") || strings.Contains(lower, "client.timeout") {
					hasTimeout = true
				}
			}
			if !found && hasHTTPGet && !hasTimeout && httpLine >= 0 {
				detail := FindingDetail{
					RuleID:      rule.ID,
					Severity:    "低风险",
					Title:       rule.Name,
					Description: "检测到网络请求缺少超时控制。",
					Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), httpLine+1),
					CodeSnippet: formatCodeContext(lines, httpLine, 2),
				}
				details = append(details, detail)
				found = true
			}
			if found {
				break
			}
		}
		if !found && len(skill.Files) > 0 {
			details = append(details, FindingDetail{
				RuleID:      rule.ID,
				Severity:    "低风险",
				Title:       rule.Name,
				Description: "存在资源耗尽风险。",
				Location:    filepath.Base(skill.Files[0].Path),
				CodeSnippet: "未定位到具体行，请检查死循环、无限递归或缺少超时的网络请求。",
			})
		}
	}
	return score, false, "", details
}

func isCommentLikeLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "--")
}

func isLowSignalExamplePath(path string) bool {
	normalized := strings.ToLower(filepath.ToSlash(path))
	parts := strings.Split(normalized, "/")
	for _, part := range parts {
		switch part {
		case "docs", "doc", "examples", "example", "fixtures", "fixture", "testdata", "samples", "sample":
			return true
		case "tests", "test", "__tests__", "spec":
			return true
		}
	}
	base := filepath.Base(normalized)
	return strings.HasSuffix(base, "_test.go") ||
		strings.HasSuffix(base, ".test.js") ||
		strings.HasSuffix(base, ".test.ts") ||
		strings.HasSuffix(base, ".spec.js") ||
		strings.HasSuffix(base, ".spec.ts") ||
		strings.HasSuffix(base, ".md")
}

func isProductionSourceFile(path string) bool {
	if isLowSignalExamplePath(path) {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go", ".py", ".js", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh", ".rb", ".php", ".java", ".cs", ".rs", ".yml", ".yaml", ".json", ".toml", ".mjs", ".cjs":
		return true
	default:
		return ext == ""
	}
}

func looksLikeSensitiveCredentialAccess(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" {
		return false
	}
	for _, marker := range []string{"/etc/shadow", "/root/.netrc", "~/.ssh", "id_rsa", "credentials.json", "credentials.yaml", "credentials.yml", "secret_access_key", "aws_access_key_id", "authorization:"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	if regexp.MustCompile(`(?i)(os\.environ|getenv\(|os\.getenv\(|process\.env)`).MatchString(line) && regexp.MustCompile(`(?i)(token|secret|password|api[_-]?key|credential|auth)`).MatchString(line) {
		return true
	}
	if regexp.MustCompile(`(?i)(readfile|open\(|read_text\(|read\()`).MatchString(line) && regexp.MustCompile(`(?i)(\.env\b|\.netrc\b|\.npmrc\b|\.pypirc\b|id_rsa|credentials?|secret|token)`).MatchString(line) {
		return true
	}
	return false
}

func looksLikeNetworkExecution(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || isCommentLikeLine(trimmed) {
		return false
	}
	return regexp.MustCompile(`(?i)(requests\.(get|post|put|delete|head|request)\(|fetch\(|axios\.(get|post|put|delete|request)\(|http\.(Get|Post|NewRequest)\(|urllib\.request\.(urlopen|Request|urlretrieve)\(|client\.do\(|net\.dial\(|curl\s+[^#\n]*https?://|wget\s+[^#\n]*https?://)`).MatchString(trimmed)
}

func looksLikeCommandExecution(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || isCommentLikeLine(trimmed) {
		return false
	}
	return regexp.MustCompile(`(?i)(subprocess\.(run|popen|call|check_call|check_output)\(|os\.system\(|exec\.Command\(|child_process\.(exec|spawn|execfile|fork)\(|Runtime\.getRuntime\(\)\.exec\(|system\(|popen\(|eval\()`).MatchString(trimmed)
}

func looksLikeDestructiveExecution(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || isCommentLikeLine(trimmed) {
		return false
	}
	if regexp.MustCompile(`(?i)(os\.(remove|unlink)\(|shutil\.rmtree\(|fs\.rm\()`).MatchString(trimmed) {
		return true
	}
	if regexp.MustCompile(`(?i)\b(rm\s+-rf\s+[/~.$\w-])`).MatchString(trimmed) {
		return regexp.MustCompile(`(?i)(^rm\s+-rf\b|os\.system\(|subprocess\.(run|popen|call|check_call|check_output)\(|exec\.Command\(|child_process\.(exec|spawn|execfile)\(|bash\s+-c|sh\s+-c)`).MatchString(trimmed)
	}
	if regexp.MustCompile(`(?i)(delete\s+from\s+[a-z_][\w.]*|drop\s+table\s+(if\s+exists\s+)?[a-z_][\w.]*|truncate\s+table\s+[a-z_][\w.]*)`).MatchString(trimmed) {
		return regexp.MustCompile(`(?i)(execute\(|exec\(|query\(|cursor\.|db\.|conn\.|session\.)`).MatchString(trimmed)
	}
	return false
}

func looksLikeMaliciousPersistenceOrC2(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || isCommentLikeLine(trimmed) {
		return false
	}
	if regexp.MustCompile(`(?i)(xmrig|stratum\+tcp|coinhive|crontab\s+-|command\s*and\s*control|/api/(checkin|beacon)|beacon\s*\(|heartbeat\s*\(|callback\s*\()`).MatchString(trimmed) {
		return true
	}
	if regexp.MustCompile(`(?i)(authorized_keys|launchctl|systemctl\s+enable|startup folder)`).MatchString(trimmed) &&
		regexp.MustCompile(`(?i)(write|append|copy|install|tee|echo|cat\s+>>|add-content|set-content|save)`).MatchString(trimmed) {
		return true
	}
	return false
}

func isLikelyLogOnlyLine(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" {
		return false
	}
	if !(strings.Contains(lower, "log_event(") || strings.Contains(lower, "logger.") || strings.Contains(lower, "log.")) {
		return false
	}
	return !strings.Contains(lower, "=") && !strings.Contains(lower, "set") && !strings.Contains(lower, "cache") && !strings.Contains(lower, "store")
}

func (e *Evaluator) evaluateMemoryIsolationFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := rule.Weight
	var details []FindingDetail

	actionKeys := []string{"memory.write", "memory.read", "memory.share", "context.set", "context.get", "state.set", "state.get", "cache"}
	controlKeys := []string{"tenant", "namespace", "user_id", "session_id", "scope", "isolation", "permission", "acl", "隔离", "权限"}
	scopeKeys := []string{"global", "shared", "cross-task", "cross user", "all user", "跨任务", "跨用户"}

	phase1Hit := false
	phase2Protected := false
	phase3Scoped := false

	for _, file := range skill.Files {
		lines := strings.Split(file.AnalysisContent(), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isCommentLikeLine(trimmed) {
				continue
			}
			lower := strings.ToLower(trimmed)
			if containsAny(lower, actionKeys...) {
				phase1Hit = true
				if containsAny(lower, scopeKeys...) {
					phase3Scoped = true
				}
				window := joinNearbyLines(lines, i, 2)
				if containsAny(strings.ToLower(window), controlKeys...) {
					phase2Protected = true
				}
				if !phase2Protected {
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    "低风险",
						Title:       rule.Name,
						Description: "三段判定命中：存在记忆/上下文共享语义，且缺少命名空间或权限隔离控制。",
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
				}
			}
		}
	}

	if !phase1Hit || (phase1Hit && phase2Protected) {
		return score, false, "", nil
	}
	if phase3Scoped {
		score = rule.Weight * 0.35
	} else {
		score = rule.Weight * 0.6
	}
	return score, false, "", details
}

func (e *Evaluator) evaluateSSRFProtectionFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := rule.Weight
	var details []FindingDetail

	requestKeys := []string{"http.get(", "http.post(", "requests.get(", "requests.post(", "fetch(", "client.do("}
	inputKeys := []string{"input", "user", "query", "param", "url", "uri", "req.", "request."}
	controlKeys := []string{"allowlist", "whitelist", "denylist", "parseurl", "validate", "isprivateip", "net.parseip", "校验", "白名单"}
	internalTargets := []string{"127.0.0.1", "localhost", "169.254.169.254", "metadata.google", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3"}

	phase1Hit := false
	phase2Protected := false
	phase3Scoped := false

	for _, file := range skill.Files {
		lines := strings.Split(file.AnalysisContent(), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isCommentLikeLine(trimmed) {
				continue
			}
			lower := strings.ToLower(trimmed)
			if containsAny(lower, requestKeys...) {
				window := strings.ToLower(joinNearbyLines(lines, i, 3))
				if !containsAny(window, inputKeys...) {
					continue
				}
				phase1Hit = true
				if containsAny(window, controlKeys...) {
					phase2Protected = true
				}
				if containsAny(window, internalTargets...) {
					phase3Scoped = true
				}
				if !phase2Protected {
					sev := "中风险"
					desc := "三段判定命中：用户可控输入参与外部请求，且未识别到目标校验/白名单控制。"
					if phase3Scoped {
						sev = "高风险"
						desc = "三段判定命中：用户可控输入参与请求，且存在内网/元数据目标范围，未识别到校验控制。"
					}
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    sev,
						Title:       rule.Name,
						Description: desc,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
				}
			}
		}
	}

	if !phase1Hit || (phase1Hit && phase2Protected) {
		return score, false, "", nil
	}
	if phase3Scoped {
		score = rule.Weight * 0.25
	} else {
		score = rule.Weight * 0.55
	}
	return score, false, "", details
}

func (e *Evaluator) evaluateLicenseValidationConfigFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	details := make([]FindingDetail, 0)
	for _, file := range skill.Files {
		if isLowSignalExamplePath(file.Path) {
			continue
		}
		lines := strings.Split(file.Content, "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isCommentLikeLine(trimmed) {
				continue
			}
			window := strings.ToLower(joinNearbyLines(lines, i, 2))
			switch {
			case isLicenseConfigCandidateLine(file.Path, window) && regexp.MustCompile(`(?i)(localhost|127\.0\.0\.1|http://|license[_ -]?server|endpoint|server|url|mock)`).MatchString(window):
				details = append(details, FindingDetail{RuleID: rule.ID, Severity: "高风险", Title: rule.Name, Description: "许可证验证使用本地默认服务、mock 服务或明文地址。", Location: fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1), CodeSnippet: formatCodeContext(lines, i, 2)})
			case isLicenseConfigCandidateLine(file.Path, window) && regexp.MustCompile(`(?i)(fail[_ -]?open|bypass|ignore|continue|skip|验证失败.*继续|绕过)`).MatchString(window):
				details = append(details, FindingDetail{RuleID: rule.ID, Severity: "高风险", Title: rule.Name, Description: "许可证验证失败分支存在放行或绕过语义。", Location: fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1), CodeSnippet: formatCodeContext(lines, i, 2)})
			case regexp.MustCompile(`(?i)(verify|validate|activate|entitlement).*(return\s+true|always\s+true)`).MatchString(window):
				details = append(details, FindingDetail{RuleID: rule.ID, Severity: "高风险", Title: rule.Name, Description: "授权校验可能被固定为成功。", Location: fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1), CodeSnippet: formatCodeContext(lines, i, 2)})
			}
		}
	}
	if len(details) == 0 {
		return rule.Weight, false, "", nil
	}
	if rule.OnFail.Action == "block" {
		return 0, true, rule.OnFail.Reason, details
	}
	return rule.Weight * 0.4, false, "", details
}

func (e *Evaluator) evaluatePathTraversalFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	patterns := []patternRisk{
		{regexp.MustCompile(`(?i)(open|readfile|writefile|read_file|write_file|os\.open|ioutil\.ReadFile|os\.ReadFile).*\.\./`), "文件 API 使用路径遍历片段"},
		{regexp.MustCompile(`(?i)(filepath\.Join|path\.join|os\.path\.join).*?(input|param|query|user|request)`), "用户输入参与文件路径拼接"},
		{regexp.MustCompile(`(?i)(/etc/passwd|/root/|~/.ssh|\.ssh/)`), "访问敏感系统路径"},
	}
	return e.evaluatePatternRiskFunc(skill, rule, "高风险", patterns)
}

func (e *Evaluator) evaluateInputSchemaFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	patterns := []patternRisk{
		{regexp.MustCompile(`(?i)(json\.loads|JSON\.parse|yaml\.safe_load|req\.body|request\.json|input\()`), "输入解析附近未识别到 Schema 或校验控制"},
		{regexp.MustCompile(`(?i)(args|kwargs|params|query).*?(exec|eval|system|shell)`), "动态参数进入高危执行路径，缺少输入 Schema 约束"},
		{regexp.MustCompile(`(?i)(jsonschema|ajv|zod|pydantic|validate\s*\(\s*schema)`), "发现输入 Schema 相关实现，需要确认是否覆盖外部输入边界"},
	}
	return e.evaluatePatternRiskFunc(skill, rule, "中风险", patterns)
}

func (e *Evaluator) evaluateAuditLoggingFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	patterns := []patternRisk{
		{regexp.MustCompile(`(?i)(log|logger|print|fmt\.Print).*(password|token|secret|api[_-]?key|authorization|cookie)`), "日志或输出包含敏感字段且未识别到脱敏"},
		{regexp.MustCompile(`(?i)(audit[_-]?log|security[_-]?log|logger\.(info|warn|error)|logrus|zap\.)`), "发现审计日志相关实现，需要确认高影响操作和异常路径是否有完整审计"},
		{regexp.MustCompile(`(?i)(except|catch).*?(pass|return\s+nil|return\s+None)`), "异常路径缺少审计记录"},
	}
	return e.evaluatePatternRiskFunc(skill, rule, "中风险", patterns)
}

func (e *Evaluator) evaluateSBOMVersionLockFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	var details []FindingDetail
	for _, file := range skill.Files {
		if !isDependencyManifestPath(file.Path) {
			continue
		}
		lines := strings.Split(file.AnalysisContent(), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isCommentLikeLine(trimmed) || !hasDependencyVersionUncertainty(trimmed) {
				continue
			}
			details = append(details, FindingDetail{
				RuleID:      rule.ID,
				Severity:    "中风险",
				Title:       rule.Name,
				Description: "依赖清单中存在未锁定版本、范围版本或外部包来源，需要确认版本锁定和来源可信。",
				Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
				CodeSnippet: formatCodeContext(lines, i, 2),
			})
		}
	}
	for _, dep := range skill.Dependencies {
		if dependencyVersionUncertain(dep.Version) {
			details = append(details, FindingDetail{
				RuleID:      rule.ID,
				Severity:    "中风险",
				Title:       rule.Name,
				Description: "解析到的第三方依赖缺少确定版本或使用范围版本，需要锁定版本并确认来源可信。",
				Location:    "依赖清单解析结果",
				CodeSnippet: fmt.Sprintf("%s %s", dep.Name, defaultText(dep.Version, "<未指定版本>")),
			})
		}
	}
	if len(details) == 0 {
		return rule.Weight, false, "", nil
	}
	if rule.OnFail.Action == "block" {
		return 0, true, rule.OnFail.Reason, details
	}
	return rule.Weight * 0.4, false, "", details
}

func isDependencyManifestPath(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "requirements.txt", "requirements-dev.txt", "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock",
		"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
		"go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
		"gemfile", "gemfile.lock", "cargo.toml", "cargo.lock", "composer.json", "composer.lock",
		"cyclonedx.json", "cyclonedx.xml", "sbom.json", "sbom.xml":
		return true
	default:
		return strings.Contains(base, "sbom") || strings.HasSuffix(base, ".spdx") || strings.HasSuffix(base, ".spdx.json")
	}
}

func hasDependencyVersionUncertainty(line string) bool {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "git+https://") || strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
		return true
	}
	return dependencyVersionUncertain(line)
}

func dependencyVersionUncertain(version string) bool {
	lower := strings.ToLower(strings.TrimSpace(version))
	if lower == "" || lower == "*" || lower == "latest" {
		return true
	}
	return strings.Contains(lower, ">=") || strings.Contains(lower, "<=") || strings.Contains(lower, "~=") || strings.Contains(lower, "^") || regexp.MustCompile(`(?i)(^|[\s"':])\d+(\.x|\.\*)`).MatchString(lower)
}

func (e *Evaluator) evaluateTLSProtectionFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	patterns := []patternRisk{
		{regexp.MustCompile(`(?i)InsecureSkipVerify\s*:\s*true|verify\s*=\s*false|rejectUnauthorized\s*:\s*false`), "TLS 证书校验被关闭"},
		{regexp.MustCompile(`(?i)http://[^\s"']+`), "外联地址使用明文 HTTP"},
		{regexp.MustCompile(`(?i)ssl\._create_unverified_context|CERT_NONE`), "使用不校验证书的 TLS 上下文"},
	}
	score, blocked, reason, details := e.evaluatePatternRiskFunc(skill, rule, "中风险", patterns)
	corsDetails := detectCORSWildcardCredentialRisk(skill, rule)
	if len(corsDetails) == 0 {
		return score, blocked, reason, details
	}
	details = append(details, corsDetails...)
	if rule.OnFail.Action == "block" {
		return 0, true, rule.OnFail.Reason, details
	}
	return rule.Weight * 0.4, false, "", details
}

func (e *Evaluator) evaluateFileUploadParsingFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	patterns := []patternRisk{
		{regexp.MustCompile(`(?i)(upload|multipart|multipart/form-data|formfile|UploadFile|SaveUploadedFile|request\.files|multer)`), "存在文件上传入口，需要验证类型、大小和存储位置控制"},
		{regexp.MustCompile(`(?i)(zipfile|tarfile|archive|extractall|untar|unzip).*?(input|upload|file)`), "上传文件或归档解析存在路径穿越/炸弹风险"},
		{regexp.MustCompile(`(?i)(parse|load).*?(pdf|docx|xlsx|image|xml)`), "复杂文件解析需要沙箱、大小限制和异常处理"},
	}
	return e.evaluatePatternRiskFunc(skill, rule, "中风险", patterns)
}

func (e *Evaluator) evaluateUnsafeDeserializationFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	patterns := []patternRisk{
		{regexp.MustCompile(`(?i)pickle\.loads?|pickle\.load|joblib\.load|torch\.load|yaml\.load\(|marshal\.loads?|unsafe[_-]?deserialize`), "使用不安全反序列化或模型文件加载 API"},
		{regexp.MustCompile(`(?i)(ObjectInputStream|BinaryFormatter|readObject\(|deserialize\()`), "使用高风险反序列化 API"},
	}
	return e.evaluatePatternRiskFunc(skill, rule, "低风险", patterns)
}

func (e *Evaluator) evaluateDebugBackdoorFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	patterns := []patternRisk{
		{regexp.MustCompile(`(?i)(debug\s*=\s*true|app\.run\(.*debug\s*=\s*true|DEBUG=True)`), "调试模式在代码中开启"},
		{regexp.MustCompile(`(?i)(/debug|/admin/test|test_backdoor|debug_backdoor|admin_backdoor|dev_only|mock_auth|skip_auth)`), "调试接口或测试后门疑似残留"},
	}
	return e.evaluatePatternRiskFunc(skill, rule, "低风险", patterns)
}

type patternRisk struct {
	Re   *regexp.Regexp
	Desc string
}

func detectCORSWildcardCredentialRisk(skill *Skill, rule config.Rule) []FindingDetail {
	var details []FindingDetail
	wildcardOrigin := regexp.MustCompile(`(?i)(access-control-allow-origin[^\n]*(\*|origin)|origin\s*[:=]\s*["']\*["']|allow_origins\s*[:=]\s*\[[^\]]*["']\*["']|CORS\([^\n]*(\*|origins\s*=\s*["']\*["']))`)
	credentialEnabled := regexp.MustCompile(`(?i)(access-control-allow-credentials[^\n]*true|credentials\s*[:=]\s*true|supports_credentials\s*[:=]\s*true|allow_credentials\s*[:=]\s*true)`)
	allowlistGuard := regexp.MustCompile(`(?i)(allowlist|allowed_origins|trusted_origins|origin_allowlist|白名单|可信域名)`)

	for _, file := range skill.Files {
		if isLowSignalExamplePath(file.Path) {
			continue
		}
		lines := strings.Split(file.AnalysisContent(), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isCommentLikeLine(trimmed) {
				continue
			}
			window := joinNearbyLines(lines, i, 4)
			if wildcardOrigin.MatchString(window) && credentialEnabled.MatchString(window) && !allowlistGuard.MatchString(window) {
				details = append(details, FindingDetail{
					RuleID:      rule.ID,
					Severity:    "中风险",
					Title:       rule.Name,
					Description: "CORS 配置同时允许通配来源和凭据，且未识别到可信来源白名单，可能导致跨站读取受保护接口。",
					Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
					CodeSnippet: formatCodeContext(lines, i, 3),
				})
				break
			}
		}
	}
	return details
}

func (e *Evaluator) evaluatePatternRiskFunc(skill *Skill, rule config.Rule, severity string, patterns []patternRisk) (float64, bool, string, []FindingDetail) {
	details := make([]FindingDetail, 0)
	for _, file := range skill.Files {
		if isLowSignalExamplePath(file.Path) {
			continue
		}
		lines := strings.Split(file.Content, "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isCommentLikeLine(trimmed) {
				continue
			}
			for _, p := range patterns {
				if p.Re.MatchString(trimmed) {
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    severity,
						Title:       rule.Name,
						Description: p.Desc,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
					break
				}
			}
		}
	}
	if len(details) == 0 {
		return rule.Weight, false, "", nil
	}
	if rule.OnFail.Action == "block" {
		return 0, true, rule.OnFail.Reason, details
	}
	return rule.Weight * 0.4, false, "", details
}

func (e *Evaluator) evaluateToolResponsePoisoningFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := rule.Weight
	var details []FindingDetail

	actionKeys := []string{"tool_response", "tooloutput", "tool output", "role:tool", "append(context", "messages.append", "system_prompt", "prompt +="}
	mergeKeys := []string{"append", "concat", "merge", "inject", "拼接", "合并"}
	protectKeys := []string{"sanitize", "filter", "schema", "validate", "allowlist", "escape", "strip", "清洗", "校验", "过滤"}
	scopeKeys := []string{"system", "exec", "command", "eval", "shell", "权限", "提权"}

	phase1Hit := false
	phase2Protected := false
	phase3Scoped := false

	for _, file := range skill.Files {
		lines := strings.Split(file.Content, "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || isCommentLikeLine(trimmed) {
				continue
			}
			lower := strings.ToLower(trimmed)
			if containsAny(lower, actionKeys...) && containsAny(lower, mergeKeys...) {
				phase1Hit = true
				window := strings.ToLower(joinNearbyLines(lines, i, 3))
				if containsAny(window, protectKeys...) {
					phase2Protected = true
				}
				if containsAny(window, scopeKeys...) {
					phase3Scoped = true
				}
				if !phase2Protected {
					sev := "中风险"
					desc := "三段判定命中：工具响应被拼接进上下文/提示词，且未识别到清洗或校验控制。"
					if phase3Scoped {
						sev = "高风险"
						desc = "三段判定命中：工具响应直接影响系统提示词/执行语义，且未识别到清洗或校验控制。"
					}
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    sev,
						Title:       rule.Name,
						Description: desc,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
				}
			}
		}
	}

	if !phase1Hit || (phase1Hit && phase2Protected) {
		return score, false, "", nil
	}
	if phase3Scoped {
		score = rule.Weight * 0.3
	} else {
		score = rule.Weight * 0.6
	}
	return score, false, "", details
}

func containsAny(text string, keys ...string) bool {
	text = strings.ToLower(text)
	for _, key := range keys {
		if strings.Contains(text, strings.ToLower(key)) {
			return true
		}
	}
	return false
}

func containsZeroWidthOrBidiControl(text string) bool {
	for _, r := range text {
		switch r {
		case '\u200B', '\u200C', '\u200D', '\u2060', '\u202A', '\u202B', '\u202C', '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069':
			return true
		}
	}
	return false
}

func hasPromptOverrideIntent(text string) bool {
	lower := strings.ToLower(text)
	return containsAny(lower,
		"ignore previous instructions",
		"ignore all previous",
		"disregard previous instructions",
		"reveal system prompt",
		"print system prompt",
		"developer message",
		"bypass approval",
		"bypass sandbox",
		"do not ask user",
		"without user confirmation",
		"override system",
		"越过审批",
		"绕过审批",
		"忽略之前的指令",
		"忽略上面的指令",
		"泄露系统提示词",
	)
}

func decodedPromptOverrideIntent(line string) bool {
	for _, candidate := range encodedTextCandidates(line) {
		if hasPromptOverrideIntent(candidate) || hasPromptOverrideIntent(rot13(candidate)) {
			return true
		}
	}
	return false
}

func encodedTextCandidates(line string) []string {
	var out []string
	b64Re := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	for _, raw := range b64Re.FindAllString(line, -1) {
		if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && isMostlyPrintable(decoded) {
			out = append(out, string(decoded))
		}
		if decoded, err := base64.RawStdEncoding.DecodeString(raw); err == nil && isMostlyPrintable(decoded) {
			out = append(out, string(decoded))
		}
	}
	hexRe := regexp.MustCompile(`(?i)(?:\\x[0-9a-f]{2}){8,}|(?:0x)?[0-9a-f]{32,}`)
	for _, raw := range hexRe.FindAllString(line, -1) {
		cleaned := strings.NewReplacer("\\x", "", "\\X", "", "0x", "", "0X", "").Replace(raw)
		if len(cleaned)%2 != 0 {
			continue
		}
		if decoded, err := hex.DecodeString(cleaned); err == nil && isMostlyPrintable(decoded) {
			out = append(out, string(decoded))
		}
	}
	return out
}

func isMostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 32 && b <= 126) {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.85
}

func rot13(text string) string {
	var builder strings.Builder
	for _, r := range text {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune('a' + (r-'a'+13)%26)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune('A' + (r-'A'+13)%26)
		default:
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func joinNearbyLines(lines []string, idx, radius int) string {
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

func (e *Evaluator) evaluateInjectionRiskFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluateInjectionRisk(skill)
	var details []FindingDetail
	if score < rule.Weight {
		found := false
		for _, file := range skill.Files {
			if isLowSignalExamplePath(file.Path) {
				continue
			}
			lines := strings.Split(file.AnalysisContent(), "\n")
			for i, line := range lines {
				if (strings.Contains(line, "exec.Command") && strings.Contains(line, "input")) ||
					(strings.Contains(line, "os.system") && strings.Contains(line, "input")) ||
					(strings.Contains(line, "eval(")) ||
					hasPromptOverrideIntent(line) || decodedPromptOverrideIntent(line) {
					desc := "存在命令注入风险。"
					if hasPromptOverrideIntent(line) || decodedPromptOverrideIntent(line) {
						desc = "检测到直接或编码隐藏的提示词覆盖/越权指令，可能诱导模型忽略上层指令或绕过审批。"
					}
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "中风险",
						Title:       rule.Name,
						Description: desc,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found && len(skill.Files) > 0 {
			details = append(details, FindingDetail{
				RuleID:      rule.ID,
				Severity:    "中风险",
				Title:       rule.Name,
				Description: "存在命令注入风险。",
				Location:    filepath.Base(skill.Files[0].Path),
				CodeSnippet: "未定位到具体行，请检查动态命令执行或 eval 调用。",
			})
		}
	}
	return score, false, "", details
}

// locateRiskInFiles 根据 LLM 风险描述尝试在代码中定位具体行
func (e *Evaluator) locateRiskInFiles(skill *Skill, risk llm.RiskItem) (location, snippet string, found bool) {
	text := strings.ToLower(risk.Title + " " + risk.Description)

	// 硬编码敏感信息
	if strings.Contains(text, "hardcode") || strings.Contains(text, "硬编码") {
		patterns := []string{
			`(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']+["']`,
			`(?i)(api[_-]?key|apikey|secret|token)\s*[:=]\s*["'][^"']+["']`,
			`(?i)(private[_-]?key|privkey)\s*[:=]\s*["'][^"']+["']`,
		}
		for _, file := range skill.Files {
			lines := strings.Split(file.AnalysisContent(), "\n")
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
					continue
				}
				for _, pat := range patterns {
					if matched, _ := regexp.MatchString(pat, line); matched {
						return fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
							formatCodeContext(lines, i, 2), true
					}
				}
			}
		}
	}

	// 许可证/配置问题
	if strings.Contains(text, "license") || strings.Contains(text, "许可证") {
		for _, file := range skill.Files {
			if isLowSignalExamplePath(file.Path) {
				continue
			}
			lines := strings.Split(file.AnalysisContent(), "\n")
			for i := range lines {
				if isLicenseConfigCandidateLine(file.Path, joinNearbyLines(lines, i, 2)) {
					return fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						formatCodeContext(lines, i, 2), true
				}
			}
		}
	}

	// 错误处理问题：查找仅记录日志但未返回或处理的错误
	if strings.Contains(text, "error") && (strings.Contains(text, "handling") || strings.Contains(text, "处理")) {
		for _, file := range skill.Files {
			lines := strings.Split(file.AnalysisContent(), "\n")
			for i, line := range lines {
				if matched, _ := regexp.MatchString(`log.*(Error|error|ERROR).*\)\s*$`, line); matched {
					return fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						formatCodeContext(lines, i, 2), true
				}
			}
		}
	}

	// 未找到，回退静态分析
	if result := e.runStaticAnalysis(skill); result != nil && len(result.DangerousCalls) > 0 {
		call := result.DangerousCalls[0]
		return fmt.Sprintf("证据: 行 %d", call.Line), fmt.Sprintf("危险调用: %s", call.Function), true
	}
	return "", "", false
}

// extractKeywordsFromRisk 从风险标题/描述中提取搜索关键词
func extractKeywordsFromRisk(risk llm.RiskItem) []string {
	text := strings.ToLower(risk.Title + " " + risk.Description)
	var keywords []string
	if strings.Contains(text, "硬编码") || strings.Contains(text, "hardcode") {
		keywords = append(keywords, "private_key", "apikey", "password", "secret", "token")
	}
	if strings.Contains(text, "许可证") || strings.Contains(text, "license") {
		keywords = append(keywords, "license", "verify", "localhost:8080")
	}
	if strings.Contains(text, "输入验证") || strings.Contains(text, "validation") {
		keywords = append(keywords, "input", "validate", "sanitize")
	}
	// 默认返回通用敏感词
	if len(keywords) == 0 {
		keywords = []string{"key", "secret", "token", "password", "http://", "https://"}
	}
	return keywords
}
