package evaluator

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"skill-scanner/internal/analyzer"
	"skill-scanner/internal/config"
	"skill-scanner/internal/embedder"
	"skill-scanner/internal/llm"
	"skill-scanner/internal/logx"
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
	Passed              bool                         `json:"passed"`
	Score               float64                      `json:"score"`
	ItemScores          map[string]float64           `json:"item_scores"`
	DetectionErrors     []DetectionError             `json:"detection_errors,omitempty"`
	RiskLevel           string                       `json:"risk_level"`
	Analysis            *analyzer.CodeAnalysisResult `json:"analysis,omitempty"`
	IntentAnalysis      *llm.AnalysisResult          `json:"intent_analysis,omitempty"`
	IntentAnalysisError string                       `json:"intent_analysis_error,omitempty"`
	FindingDetails      []FindingDetail              `json:"finding_details,omitempty"`
}

type DetectionError struct {
	RuleID   string `json:"rule_id"`
	Kind     string `json:"kind"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
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
	osvClient  osvQueryClient
	funcMap    map[string]DetectionFunc
	patternMap map[string][]*regexp.Regexp
	codePatternMap map[string][]*regexp.Regexp // code_vs_docs: ruleID → code_patterns
	docPatternMap  map[string][]*regexp.Regexp // code_vs_docs / artifact_vs_docs: ruleID → doc_patterns
	artifactPatternMap map[string][]*regexp.Regexp // artifact_vs_docs: ruleID → artifact_patterns
	thresholds Thresholds
	cache      *lru.Cache[string, CacheItem]
	cacheMutex sync.RWMutex
	progressFn func(ProgressEvent)
}

const (
	defaultEvaluatorCacheMaxEntries = 10000
	defaultEvaluatorCacheTTL        = 24 * time.Hour
	evaluatorAuditPolicyVersion     = "audit-policy"
	evaluatorPromptTemplateVersion  = "llm-prompt"
	evaluatorSchemaVersion          = "finding-schema"
	maxLLMIntentSummaryBytes        = 8192
	maxLLMIntentSummaryBytesPerFile = 1200
	maxLLMIntentFileInputBytes      = 6000
	llmIntentFileConcurrency        = 4
)

type ProgressEvent struct {
	Layer    string
	RuleID   string
	RuleName string
	Index    int
	Total    int
}

type osvQueryClient interface {
	QueryBatch(ctx context.Context, queries []osvPackageQuery) ([]osvQueryResult, error)
}

type osvPackageQuery struct {
	Ecosystem string
	Name      string
	Version   string
}

type osvQueryResult struct {
	Vulns []osvVulnerability
}

type osvVulnerability struct {
	ID       string
	Summary  string
	Modified string
}

type osvHTTPClient struct {
	baseURL    string
	httpClient *http.Client
}

// DetectionFunc 检测函数签名
type DetectionFunc func(skill *Skill, rule config.Rule) (score float64, blocked bool, reason string, details []FindingDetail, err error)

type declaredSkillCapabilities struct {
	network       bool
	command       bool
	sensitiveFile bool
	destructive   bool
	autoTrading   bool
}

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
	cacheSize := config.EvaluatorCacheMaxEntries()
	if cacheSize <= 0 {
		cacheSize = defaultEvaluatorCacheMaxEntries
	}
	cache, err := lru.New[string, CacheItem](cacheSize)
	if err != nil {
		cache, _ = lru.New[string, CacheItem](1)
	}
	e := &Evaluator{
		embedder:           embedder,
		llmClient:          llmClient,
		config:             cfg,
		osvClient:          newOSVHTTPClient(),
		funcMap:            make(map[string]DetectionFunc),
		patternMap:         make(map[string][]*regexp.Regexp),
		codePatternMap:     make(map[string][]*regexp.Regexp),
		docPatternMap:      make(map[string][]*regexp.Regexp),
		artifactPatternMap: make(map[string][]*regexp.Regexp),
		thresholds:         DefaultThresholds,
		cache:              cache,
	}
	e.registerBuiltinFuncs()
	e.buildPatternCache()
	return e
}

func newOSVHTTPClient() osvQueryClient {
	return &osvHTTPClient{
		baseURL: "https://api.osv.dev/v1/querybatch",
		httpClient: &http.Client{
			Timeout: 8 * time.Second,
		},
	}
}

func (c *osvHTTPClient) QueryBatch(ctx context.Context, queries []osvPackageQuery) ([]osvQueryResult, error) {
	if c == nil || len(queries) == 0 {
		return nil, nil
	}
	type osvBatchRequest struct {
		Queries []struct {
			Version string `json:"version,omitempty"`
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
		} `json:"queries"`
	}
	type osvBatchResponse struct {
		Results []struct {
			Vulns []struct {
				ID       string `json:"id"`
				Summary  string `json:"summary"`
				Modified string `json:"modified"`
			} `json:"vulns"`
		} `json:"results"`
	}
	payload := osvBatchRequest{Queries: make([]struct {
		Version string `json:"version,omitempty"`
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
	}, 0, len(queries))}
	for _, item := range queries {
		if strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.Version) == "" || strings.TrimSpace(item.Ecosystem) == "" {
			continue
		}
		query := struct {
			Version string `json:"version,omitempty"`
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
		}{Version: strings.TrimSpace(item.Version)}
		query.Package.Name = strings.TrimSpace(item.Name)
		query.Package.Ecosystem = strings.TrimSpace(item.Ecosystem)
		payload.Queries = append(payload.Queries, query)
	}
	if len(payload.Queries) == 0 {
		return nil, nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("osv query failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	var decoded osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}
	results := make([]osvQueryResult, 0, len(decoded.Results))
	for _, item := range decoded.Results {
		result := osvQueryResult{Vulns: make([]osvVulnerability, 0, len(item.Vulns))}
		for _, vuln := range item.Vulns {
			result.Vulns = append(result.Vulns, osvVulnerability{ID: vuln.ID, Summary: vuln.Summary, Modified: vuln.Modified})
		}
		results = append(results, result)
	}
	return results, nil
}

func (e *Evaluator) buildPatternCache() {
	if e == nil || e.config == nil {
		return
	}
	for _, rule := range e.config.Rules {
		detType := strings.TrimSpace(rule.Detection.Type)
		ruleID := strings.TrimSpace(rule.ID)
		if ruleID == "" {
			continue
		}
		d := rule.Detection

		// 主 patterns（pattern / forbid_pattern / require_pattern / require_file_presence）
		if detType == "pattern" || detType == "forbid_pattern" || detType == "require_pattern" || detType == "require_file_presence" {
			e.patternMap[ruleID] = compilePatterns(rule.ID, d.Patterns)
		}

		// code_vs_docs: code_patterns + doc_patterns
		if detType == "code_vs_docs" {
			e.codePatternMap[ruleID] = compilePatterns(rule.ID, d.CodePatterns)
			e.docPatternMap[ruleID] = compilePatterns(rule.ID, d.DocPatterns)
		}

		// artifact_vs_docs: artifact_patterns + doc_patterns
		if detType == "artifact_vs_docs" {
			e.artifactPatternMap[ruleID] = compilePatterns(rule.ID, d.ArtifactPatterns)
			e.docPatternMap[ruleID] = compilePatterns(rule.ID, d.DocPatterns)
		}
	}
}

func compilePatterns(ruleID string, patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pat := range patterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			logx.With("component", "evaluator", "rule_id", ruleID, "pattern", pat, "error", err.Error()).Warn("invalid regex pattern skipped")
			continue
		}
		compiled = append(compiled, re)
	}
	return compiled
}

func (e *Evaluator) registerBuiltinFuncs() {
	e.funcMap["detectDataExfiltration"] = e.detectDataExfiltrationFunc
	e.funcMap["detectHardcodedCredential"] = e.detectHardcodedCredentialFunc
	e.funcMap["detectMCPAbuse"] = e.detectMCPAbuseFunc
	e.funcMap["detectEnvironmentEvasion"] = e.detectEnvironmentEvasionFunc
	e.funcMap["evaluateIrreversibleOpsApproval"] = e.evaluateIrreversibleOpsApprovalFunc
	e.funcMap["evaluateDataMinimizationEvidence"] = e.evaluateDataMinimizationEvidenceFunc
	e.funcMap["evaluateDependencyVulns"] = e.evaluateDependencyVulnsFunc
	e.funcMap["evaluateTyposquatRisk"] = e.evaluateTyposquatRiskFunc
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

func (e *Evaluator) SetProgressHook(fn func(ProgressEvent)) {
	e.progressFn = fn
}

func (e *Evaluator) emitProgress(layer, ruleID, ruleName string, index, total int) {
	if e.progressFn == nil {
		return
	}
	e.progressFn(ProgressEvent{
		Layer:    strings.TrimSpace(layer),
		RuleID:   strings.TrimSpace(ruleID),
		RuleName: strings.TrimSpace(ruleName),
		Index:    index,
		Total:    total,
	})
}

type CacheKey struct {
	CodeHash              string
	DescHash              string
	DepsHash              string
	PermissionsHash       string
	AuditPolicyVersion    string
	PromptTemplateVersion string
	SchemaVersion         string
	LLMClientFingerprint  string
}

func (c *CacheKey) String() string {
	return fmt.Sprintf("eval:%s:%s:%s:%s:%s:%s:%s:%s", c.CodeHash[:8], c.DescHash[:8], c.DepsHash[:8], c.PermissionsHash[:8], c.AuditPolicyVersion, c.PromptTemplateVersion, c.SchemaVersion, c.LLMClientFingerprint[:8])
}

func generateCacheKey(skill *Skill, llmClient llm.Client) CacheKey {
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
		CodeHash:              hex.EncodeToString(codeHash[:]),
		DescHash:              hex.EncodeToString(descHash[:]),
		DepsHash:              hex.EncodeToString(depsHash[:]),
		PermissionsHash:       hex.EncodeToString(permHash[:]),
		AuditPolicyVersion:    evaluatorAuditPolicyVersion,
		PromptTemplateVersion: evaluatorPromptTemplateVersion,
		SchemaVersion:         evaluatorSchemaVersion,
		LLMClientFingerprint:  llmClientFingerprint(llmClient),
	}
}

func llmClientFingerprint(client llm.Client) string {
	value := "none"
	if client != nil {
		value = reflect.TypeOf(client).String()
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// Evaluate 审查技能（所有规则平等参与，无优先级阻断）
func (e *Evaluator) Evaluate(ctx context.Context, skill *Skill) (*EvaluationResult, error) {
	cacheKey := generateCacheKey(skill, e.llmClient)
	cacheStr := cacheKey.String()
	if item, ok := e.getCachedResult(cacheStr); ok {
		return item.Result, nil
	}

	result := &EvaluationResult{
		Passed:     true,
		Score:      100,
		ItemScores: make(map[string]float64),
		RiskLevel:  "low",
		Analysis:   e.runStaticAnalysis(skill),
	}

	// 1. 执行所有规则（合并相邻行，去重文件）
	detailMap := make(map[string]*FindingDetail) // 键：文件路径+规则ID

	totalRules := len(e.config.Rules)
	ruleIndex := 0
	for _, rule := range e.config.Rules {
		ruleIndex++
		e.emitProgress(rule.Layer, rule.ID, rule.Name, ruleIndex, totalRules)
		if rule.Detection.Type == "pattern" {
			// 按文件分组匹配行
			matchedAny := false
			compiledPatterns := e.patternMap[strings.TrimSpace(rule.ID)]
			if len(compiledPatterns) == 0 {
				result.ItemScores[rule.ID] = rule.Weight
				continue
			}
			for _, file := range skill.Files {
				lines := strings.Split(file.AnalysisContent(), "\n")
				matchedLines := make(map[int]bool) // 记录哪些行匹配
				for lineNum, line := range lines {
					// 过滤注释行和行内注释
					codeLine := stripInlineComment(line)
					if codeLine == "" {
						continue
					}
					for _, re := range compiledPatterns {
						if re.MatchString(codeLine) {
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
		score, _, _, details, execErr := e.executeRule(ctx, skill, rule)
		if len(details) > 0 {
			result.FindingDetails = append(result.FindingDetails, details...)
		}
		if execErr != nil {
			appendDetectionError(result, rule.ID, execErr)
		}
		result.ItemScores[rule.ID] = score
	}

	// 将合并后的详情存入 result
	for _, detail := range detailMap {
		result.FindingDetails = append(result.FindingDetails, *detail)
	}

	// 2. LLM 深度分析
	ruleByID := buildRuleLookup(e.config.Rules)
	if detail, _ := e.buildStaticIntentAlignmentFinding(skill, ruleByID); detail != nil {
		result.FindingDetails = append(result.FindingDetails, *detail)
	}
	if details, _ := e.buildStaticSkillAuditFindings(skill, ruleByID); len(details) > 0 {
		result.FindingDetails = append(result.FindingDetails, details...)
	}
	if e.llmClient != nil {
		llmResult, err := e.analyzeIntentByFile(ctx, skill)
		if err != nil {
			result.IntentAnalysisError = formatLLMIntentError(err)
			appendDetectionError(result, "LLM-INTENT", errors.New(result.IntentAnalysisError))
		} else if llmResult == nil {
			result.IntentAnalysisError = "LLM 返回空结果"
			appendDetectionError(result, "LLM-INTENT", errors.New(result.IntentAnalysisError))
		} else {
			result.IntentAnalysis = llmResult
			if detail, _ := buildLLMIntentFinding(llmResult, ruleByID); detail != nil {
				result.FindingDetails = append(result.FindingDetails, *detail)
			}
			seen := make(map[string]bool)
			for _, risk := range llmResult.Risks {
				risk = normalizeLLMRisk(risk)
				loc, snippet, found := e.locateRiskInFiles(skill, risk)
				if !found && strings.TrimSpace(risk.KeyCodeLocation) != "" {
					loc = strings.TrimSpace(risk.KeyCodeLocation)
					snippet = strings.TrimSpace(risk.Evidence)
					found = true
				}
				if !found || shouldSkipLLMRisk(risk) {
					continue // 无具体位置，不生成该项
				}
				risk = calibrateLLMRisk(risk, loc, snippet)
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
				} else if risk.Severity == "medium" {
					severity = "中风险"
				} else {
					severity = "低风险"
				}

				detail := FindingDetail{
					RuleID:      ruleID,
					Severity:    severity,
					Title:       title,
					Description: formatLLMRiskDescription(risk),
					Location:    loc,
					CodeSnippet: formatLLMRiskSnippet(risk, snippet),
				}
				result.FindingDetails = append(result.FindingDetails, detail)
			}
		}
	}

	// 2. 已在统一循环中处理所有规则（pattern 类型在上面的循环中处理，其他类型通过 executeRule）

	result.RiskLevel = aggregateEvaluationRisk(result.FindingDetails, false)
	result.Score = 0
	result.Passed = result.RiskLevel == "low"

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
	declared := detectDeclaredSkillCapabilities(declaredText)

	patterns := []struct {
		declared bool
		match    func(string) bool
		desc     string
	}{
		{declared.command, looksLikeCommandExecution, "声明未提及命令执行，但可执行代码包含 shell/子进程调用"},
		{declared.network, looksLikeNetworkExecution, "声明未提及网络访问，但可执行代码包含外联或下载能力"},
		{declared.sensitiveFile, looksLikeSensitiveCredentialAccess, "声明未提及敏感文件或用户目录访问，但代码包含真实敏感位置或凭据读取行为"},
		{declared.destructive, looksLikeDestructiveExecution, "声明未提及破坏性操作，但代码包含删除、清空或不可逆修改能力"},
		{declared.autoTrading, looksLikeAutoTradingExecution, "声明未提及真实资金自动交易或下单能力，但代码包含订单构造、签名或提交行为"},
	}

	for _, file := range skill.Files {
		if !isProductionSourceFile(file.Path) {
			continue
		}
		lines := strings.Split(file.AnalysisContent(), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if shouldSkipSemanticLine(trimmed) {
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
	declared := detectDeclaredSkillCapabilities(declaredText)

	patterns := []struct {
		declared    bool
		severity    string
		desc        string
		match       func(string) bool
		requireProd bool
	}{
		{declared.sensitiveFile, "高风险", "声明未提及敏感凭据或用户配置访问，但 Skill 脚本包含真实敏感位置或凭据读取行为。", looksLikeSensitiveCredentialAccess, true},
		{declared.network, "高风险", "声明未提及网络访问，但 Skill 脚本包含外联、下载或上传能力。", looksLikeNetworkExecution, true},
		{declared.command, "高风险", "声明未提及命令执行，但 Skill 脚本包含 shell、子进程或动态代码执行能力。", looksLikeCommandExecution, true},
		{declared.destructive, "高风险", "声明未提及破坏性操作，但 Skill 脚本包含删除、清空或不可逆修改能力。", looksLikeDestructiveExecution, true},
		{declared.autoTrading, "高风险", "声明未提及真实资金自动交易或下单能力，但 Skill 脚本包含订单构造、签名或提交行为。", looksLikeAutoTradingExecution, true},
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
			if shouldSkipSemanticLine(trimmed) || (isScript && isLikelyLogOnlyLine(trimmed)) {
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

func detectDeclaredSkillCapabilities(text string) declaredSkillCapabilities {
	text = strings.ToLower(strings.TrimSpace(text))
	return declaredSkillCapabilities{
		network:       containsAny(text, "network", "http", "api", "url", "web", "download", "fetch", "requests", "联网", "网络", "接口", "外部", "下载"),
		command:       containsAny(text, "command", "shell", "exec", "subprocess", "terminal", "命令", "终端", "执行脚本", "运行脚本"),
		sensitiveFile: containsAny(text, "credential", "token", "secret", "ssh", "env", "home", "documents", "download", "file", "凭据", "密钥", "令牌", "环境变量", "文件", "文档"),
		destructive:   containsAny(text, "delete", "remove", "cleanup", "drop", "truncate", "flash", "firmware", "ecu write", "routine control", "刷写", "写入ecu", "例程控制", "删除", "清理", "移除", "销毁"),
		autoTrading:   containsAny(text, "live trading", "trading", "trade", "order", "market order", "limit order", "create_order", "signed_order", "wallet", "真实交易", "自动交易", "下单", "订单", "资金", "钱包"),
	}
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

type llmIntentFileResult struct {
	Path   string
	Result *llm.AnalysisResult
	Error  error
}

func (e *Evaluator) analyzeIntentByFile(ctx context.Context, skill *Skill) (*llm.AnalysisResult, error) {
	if e == nil || e.llmClient == nil {
		return nil, fmt.Errorf("llm client is required")
	}
	if skill == nil {
		return nil, fmt.Errorf("skill is nil")
	}
	files := prioritizeLLMIntentFiles(skill.Files)
	if len(files) == 0 {
		return e.llmClient.AnalyzeCode(ctx, skill.Name, skill.Description, "")
	}
	workerCount := llmIntentFileConcurrency
	if len(files) < workerCount {
		workerCount = len(files)
	}
	jobs := make(chan SourceFile)
	results := make(chan llmIntentFileResult, len(files))
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range jobs {
				if ctx.Err() != nil {
					results <- llmIntentFileResult{Path: file.Path, Error: ctx.Err()}
					continue
				}
				analysis, err := e.analyzeSingleFileIntentWithRepair(ctx, skill, file)
				results <- llmIntentFileResult{Path: file.Path, Result: analysis, Error: err}
			}
		}()
	}
	for _, file := range files {
		jobs <- file
	}
	close(jobs)
	wg.Wait()
	close(results)
	parts := make([]llmIntentFileResult, 0, len(files))
	for item := range results {
		parts = append(parts, item)
	}
	sort.SliceStable(parts, func(i, j int) bool {
		return llmIntentFilePriority(SourceFile{Path: parts[i].Path}) < llmIntentFilePriority(SourceFile{Path: parts[j].Path})
	})
	return mergeLLMIntentFileResults(parts)
}

func (e *Evaluator) analyzeSingleFileIntentWithRepair(ctx context.Context, skill *Skill, file SourceFile) (*llm.AnalysisResult, error) {
	if e == nil || e.llmClient == nil {
		return nil, fmt.Errorf("llm client is required")
	}
	name := skill.Name + " / " + filepath.Base(file.Path)
	inputs := []string{
		buildLLMIntentFileSummary(file, maxLLMIntentFileInputBytes),
		buildLLMIntentFileSummary(file, maxLLMIntentSummaryBytesPerFile),
	}
	var lastErr error
	for attempt, input := range inputs {
		analysis, err := e.llmClient.AnalyzeCode(ctx, name, skill.Description, input)
		if err == nil && analysis != nil {
			if attempt > 0 {
				logLLMDebug("llm file analysis recovered after retry", "file", file.Path, "attempt", attempt+1)
			}
			return analysis, nil
		}
		if err == nil {
			err = fmt.Errorf("LLM 返回空结果")
		}
		lastErr = err
		logLLMDebug("llm file analysis attempt failed", "file", file.Path, "attempt", attempt+1, "error", formatLLMIntentError(err), "input_bytes", len(input))
		if ctx.Err() != nil {
			lastErr = ctx.Err()
			break
		}
	}
	logLLMDebug("llm file analysis using local fallback", "file", file.Path, "error", formatLLMIntentError(lastErr))
	return buildLocalLLMIntentFallback(file, lastErr), nil
}

func buildLLMIntentFileSummary(file SourceFile, limit int) string {
	content := strings.TrimSpace(file.AnalysisContent())
	if content == "" {
		return fmt.Sprintf("文件：%s\n语言：%s\n内容为空。", file.Path, file.Language)
	}
	if len(content) > limit {
		content = truncateStringBytes(content, limit)
	}
	return fmt.Sprintf("文件：%s\n语言：%s\n以下是该单个文件的隔离分析内容：\n<<<UNTRUSTED_FILE_CONTENT\n%s\nUNTRUSTED_FILE_CONTENT>>>", file.Path, file.Language, content)
}

func buildLocalLLMIntentFallback(file SourceFile, cause error) *llm.AnalysisResult {
	content := file.AnalysisContent()
	lower := strings.ToLower(content)
	actualCapabilities := []string{"本地静态兜底分析"}
	risks := make([]llm.RiskItem, 0, 3)
	if containsAny(lower, "exec(", "eval(", "os.system", "subprocess", "exec.command", "shell=true") {
		actualCapabilities = appendUniqueStrings(actualCapabilities, "命令执行")
		risks = append(risks, localFallbackRisk(file, "命令执行风险", "high", "检测到命令执行相关调用，需确认输入来源和命令边界。", firstMatchingEvidenceLine(file, "exec", "eval", "os.system", "subprocess", "exec.Command", "shell=True")))
	}
	if containsAny(lower, "http://", "https://", "requests.", "http.get", "fetch(", "axios.") {
		actualCapabilities = appendUniqueStrings(actualCapabilities, "网络访问")
		risks = append(risks, localFallbackRisk(file, "网络访问需复核", "medium", "检测到外部网络访问语义，需确认是否属于声明范围。", firstMatchingEvidenceLine(file, "http://", "https://", "requests.", "http.Get", "fetch(", "axios.")))
	}
	if containsAny(lower, "password", "token", "secret", "api_key", "apikey", "private_key", "密钥", "凭据") {
		actualCapabilities = appendUniqueStrings(actualCapabilities, "凭据处理")
		risks = append(risks, localFallbackRisk(file, "凭据处理需复核", "medium", "检测到凭据或密钥相关文本，需确认是否存在硬编码或外传。", firstMatchingEvidenceLine(file, "password", "token", "secret", "api_key", "apikey", "private_key", "密钥", "凭据")))
	}
	if len(risks) == 0 {
		risks = append(risks, llm.RiskItem{Title: "本地兜底检查完成", Severity: "low", Status: "dismissed", Confidence: "medium", Description: "LLM 文件分析失败后已执行本地静态兜底检查，未发现高危关键行为信号。", Evidence: filepath.Base(file.Path), EvidenceRefs: []string{file.Path}, KeyCodeLocation: file.Path, RemediationQuality: "medium"})
	}
	causeText := "LLM 文件级分析未返回可用结果，已自动执行本地兜底分析。"
	if cause != nil {
		causeText = "LLM 文件级分析未返回可用结果，已自动执行本地兜底分析。调试原因已写入服务端日志。"
	}
	return &llm.AnalysisResult{
		StatedIntent:         "按文件隔离执行安全检查。",
		ActualBehavior:       fmt.Sprintf("%s 已完成本地兜底安全检查。", filepath.Base(file.Path)),
		IntentRiskLevel:      strongestRiskLevelFromItems(risks),
		DeclaredCapabilities: []string{"文件级安全检查"},
		ActualCapabilities:   actualCapabilities,
		ConsistencyEvidence:  []string{filepath.Base(file.Path) + ": " + causeText},
		Risks:                risks,
	}
}

func localFallbackRisk(file SourceFile, title, severity, description, evidence string) llm.RiskItem {
	if strings.TrimSpace(evidence) == "" {
		evidence = filepath.Base(file.Path)
	}
	return llm.RiskItem{Title: title, Severity: severity, Status: "needs-review", Confidence: "medium", Exploitability: "unknown", Description: description, Evidence: evidence, EvidenceRefs: []string{file.Path}, KeyCodeLocation: file.Path, Remediation: "复核该文件中对应行为是否属于声明范围；如保留该能力，需要补充最小权限边界、输入约束和失败即拒绝处理。", VerificationStep: "重新扫描该文件，确认对应本地兜底风险被 LLM 或规则链路明确确认为 dismissed 或已有证据绑定修复建议。", RemediationQuality: "medium"}
}

func strongestRiskLevelFromItems(risks []llm.RiskItem) string {
	level := "none"
	for _, risk := range risks {
		level = strongerIntentRiskLevel(level, risk.Severity)
	}
	return level
}

func firstMatchingEvidenceLine(file SourceFile, needles ...string) string {
	lines := strings.Split(file.AnalysisContent(), "\n")
	for i, line := range lines {
		lower := strings.ToLower(line)
		for _, needle := range needles {
			if strings.Contains(lower, strings.ToLower(needle)) {
				return fmt.Sprintf("%s:%d %s", filepath.Base(file.Path), i+1, strings.TrimSpace(line))
			}
		}
	}
	return filepath.Base(file.Path)
}

func logLLMDebug(msg string, args ...any) {
	if !config.LLMDebugEnabled() {
		return
	}
	logx.With(append([]any{"component", "llm-debug"}, args...)...).Warn(msg)
}

func mergeLLMIntentFileResults(parts []llmIntentFileResult) (*llm.AnalysisResult, error) {
	merged := &llm.AnalysisResult{IntentRiskLevel: "none", IntentConsistency: 100}
	success := 0
	for _, part := range parts {
		path := strings.TrimSpace(part.Path)
		if path == "" {
			path = "unknown"
		}
		if part.Error != nil {
			logLLMDebug("llm file analysis result failed before merge", "file", path, "error", formatLLMIntentError(part.Error))
			continue
		}
		if part.Result == nil {
			logLLMDebug("llm file analysis returned nil before merge", "file", path)
			continue
		}
		success++
		prefix := filepath.Base(path)
		if text := strings.TrimSpace(part.Result.StatedIntent); text != "" && merged.StatedIntent == "" {
			merged.StatedIntent = text
		}
		if text := strings.TrimSpace(part.Result.ActualBehavior); text != "" {
			merged.ActualBehavior = appendTextLine(merged.ActualBehavior, prefix+": "+text)
		}
		if text := strings.TrimSpace(part.Result.IntentMismatch); text != "" {
			merged.IntentMismatch = appendTextLine(merged.IntentMismatch, prefix+": "+text)
		}
		merged.DeclaredCapabilities = appendUniqueStrings(merged.DeclaredCapabilities, part.Result.DeclaredCapabilities...)
		merged.ActualCapabilities = appendUniqueStrings(merged.ActualCapabilities, prefixStrings(prefix+": ", part.Result.ActualCapabilities)...)
		merged.ConsistencyEvidence = appendUniqueStrings(merged.ConsistencyEvidence, prefixStrings(prefix+": ", part.Result.ConsistencyEvidence)...)
		merged.Risks = append(merged.Risks, tagRiskItemsWithFile(path, part.Result.Risks)...)
		merged.IntentRiskLevel = strongerIntentRiskLevel(merged.IntentRiskLevel, part.Result.IntentRiskLevel)
		if part.Result.IntentConsistency > 0 && part.Result.IntentConsistency < merged.IntentConsistency {
			merged.IntentConsistency = part.Result.IntentConsistency
		}
	}
	if success == 0 {
		return nil, fmt.Errorf("所有文件的 LLM 意图分析均失败且本地兜底未生成结果")
	}
	if merged.StatedIntent == "" {
		merged.StatedIntent = "已按文件隔离完成 LLM 声明意图分析。"
	}
	if merged.ActualBehavior == "" {
		merged.ActualBehavior = "各文件未返回明确的实际行为摘要。"
	}
	merged.CrossFileConsolidation = buildCrossFileConsolidation(merged.Risks, merged.ActualCapabilities, merged.ConsistencyEvidence)
	merged.ActualBehavior = appendCrossFileConsolidationSummary(merged.ActualBehavior, merged.CrossFileConsolidation)
	if merged.CrossFileConsolidation != nil {
		merged.ConsistencyEvidence = appendUniqueStrings(merged.ConsistencyEvidence, merged.CrossFileConsolidation.Evidence...)
	}
	return merged, nil
}

func appendCrossFileConsolidationSummary(base string, consolidation *llm.CrossFileConsolidation) string {
	summary := ""
	if consolidation != nil {
		summary = strings.TrimSpace(consolidation.Summary)
	}
	if strings.TrimSpace(summary) == "" {
		return base
	}
	if strings.TrimSpace(base) == "" {
		return summary
	}
	return strings.TrimSpace(base) + "\n" + summary
}

func buildCrossFileConsolidation(risks []llm.RiskItem, capabilities, evidence []string) *llm.CrossFileConsolidation {
	joined := strings.ToLower(strings.Join(append(append(flattenRiskTexts(risks), capabilities...), evidence...), " "))
	hasSource := containsAny(joined, "token", "secret", "private_key", "credential", "netrc", "读取", "collect", "采集")
	hasTransform := containsAny(joined, "serialize", "json", "payload", "拼接", "参数", "打包", "encode")
	hasSink := containsAny(joined, "requests.post", "http://", "https://", "exec", "os.system", "subprocess", "外联", "执行")
	hasRuntime := containsAny(joined, "sequence", "时序", "behavior", "runtime", "关键样本", "真实请求")
	result := &llm.CrossFileConsolidation{
		Evidence:          crossFileConsolidationEvidence(risks, capabilities),
		RelatedCategories: buildCrossFileConsolidationCategories(hasSource, hasTransform, hasSink),
		MissingParts:      buildCrossFileConsolidationMissingParts(hasSource, hasTransform, hasSink, hasRuntime),
		HasSource:         hasSource,
		HasTransform:      hasTransform,
		HasSink:           hasSink,
		HasRuntime:        hasRuntime,
	}
	if hasSource && hasSink && hasRuntime {
		if hasTransform {
			result.Summary = "跨文件链路研判: 已识别 source-transform-sink-runtime 组合信号，建议按跨文件闭环优先复核。"
			return result
		}
		result.Summary = "跨文件链路研判: 已识别 source-sink-runtime 组合信号，建议优先检查跨文件调用链。"
		return result
	}
	if hasSource && hasSink {
		result.Summary = "跨文件链路研判: 已识别 source 与 sink 分散在不同文件的组合信号，仍需补 runtime 或 transform 支撑。"
		return result
	}
	if len(result.Evidence) == 0 && len(result.RelatedCategories) == 0 {
		return nil
	}
	return result
}

func buildCrossFileConsolidationCategories(hasSource, hasTransform, hasSink bool) []string {
	out := []string{}
	if hasSource {
		out = append(out, "凭据访问", "凭据暴露")
	}
	if hasSink {
		out = append(out, "外联与情报", "命令执行", "下载执行")
	}
	if hasTransform {
		out = append(out, "数据收集与打包")
	}
	return appendUniqueStrings(nil, out...)
}

func buildCrossFileConsolidationMissingParts(hasSource, hasTransform, hasSink, hasRuntime bool) []string {
	missing := []string{}
	if !hasSource {
		missing = append(missing, "source")
	}
	if !hasTransform {
		missing = append(missing, "transform")
	}
	if !hasSink {
		missing = append(missing, "sink")
	}
	if !hasRuntime {
		missing = append(missing, "runtime")
	}
	return missing
}

func crossFileConsolidationEvidence(risks []llm.RiskItem, capabilities []string) []string {
	joined := strings.ToLower(strings.Join(append(flattenRiskTexts(risks), capabilities...), " "))
	items := []string{}
	if containsAny(joined, "token", "secret", "private_key", "credential", "netrc", "读取", "collect", "采集") {
		items = append(items, "跨文件链路研判: 已识别 source 类信号")
	}
	if containsAny(joined, "requests.post", "http://", "https://", "exec", "os.system", "subprocess", "外联", "执行") {
		items = append(items, "跨文件链路研判: 已识别 sink 类信号")
	}
	if containsAny(joined, "sequence", "时序", "behavior", "runtime", "关键样本", "真实请求") {
		items = append(items, "跨文件链路研判: 已识别 runtime 类支撑")
	}
	return items
}

func flattenRiskTexts(risks []llm.RiskItem) []string {
	out := make([]string, 0, len(risks)*4)
	for _, risk := range risks {
		out = append(out, risk.Title, risk.Description, risk.Evidence, strings.Join(risk.EvidenceRefs, " "))
	}
	return out
}

func appendTextLine(base, line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return base
	}
	if strings.TrimSpace(base) == "" {
		return line
	}
	return strings.TrimSpace(base) + "\n" + line
}

func appendUniqueStrings(base []string, values ...string) []string {
	seen := make(map[string]struct{}, len(base)+len(values))
	out := make([]string, 0, len(base)+len(values))
	for _, value := range append(append([]string{}, base...), values...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func prefixStrings(prefix string, values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, prefix+value)
		}
	}
	return out
}

func tagRiskItemsWithFile(path string, risks []llm.RiskItem) []llm.RiskItem {
	out := make([]llm.RiskItem, 0, len(risks))
	base := filepath.Base(path)
	for _, risk := range risks {
		if strings.TrimSpace(risk.KeyCodeLocation) == "" {
			risk.KeyCodeLocation = path
		}
		if len(risk.EvidenceRefs) == 0 {
			risk.EvidenceRefs = []string{path}
		}
		if strings.TrimSpace(risk.Evidence) != "" && !strings.Contains(risk.Evidence, base) {
			risk.Evidence = base + ": " + risk.Evidence
		}
		out = append(out, risk)
	}
	return out
}

func strongerIntentRiskLevel(current, next string) string {
	if intentRiskRank(next) > intentRiskRank(current) {
		return strings.ToLower(strings.TrimSpace(next))
	}
	return strings.ToLower(strings.TrimSpace(current))
}

func intentRiskRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "high", "高", "高风险":
		return 3
	case "medium", "中", "中风险":
		return 2
	case "low", "低", "低风险":
		return 1
	default:
		return 0
	}
}

func appendDetectionError(result *EvaluationResult, ruleID string, err error) {
	if result == nil || err == nil {
		return
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return
	}
	entry := DetectionError{
		RuleID:   strings.TrimSpace(ruleID),
		Kind:     classifyDetectionErrorKind(msg),
		Message:  msg,
		Severity: "warning",
	}
	for _, existing := range result.DetectionErrors {
		if existing == entry {
			return
		}
	}
	result.DetectionErrors = append(result.DetectionErrors, entry)
}

func classifyDetectionErrorKind(message string) string {
	lower := strings.ToLower(strings.TrimSpace(message))
	if strings.Contains(lower, " skipped:") {
		return "skipped"
	}
	return "failed"
}

func (e *Evaluator) executeRule(ctx context.Context, skill *Skill, rule config.Rule) (score float64, blocked bool, reason string, details []FindingDetail, err error) {
	switch rule.Detection.Type {
	case "pattern":
		// pattern 类型已经在 Evaluate 中单独处理，这里不会调用到
		return rule.Weight, false, "", nil, nil
	case "semantic":
		// 语义检测，目前不返回位置
		if e.embedder == nil {
			return rule.Weight, false, "", nil, fmt.Errorf("semantic detector unavailable: embedder is nil")
		}
		codeSummary := extractCodeSummaryFromFiles(skill.Files)
		vectors, err := e.embedder.BatchEmbed([]string{skill.Description, codeSummary})
		if err != nil {
			return rule.Weight, false, "", nil, fmt.Errorf("semantic embedding failed: %w", err)
		}
		sim := similarity.CosineSimilarity(vectors[0], vectors[1])
		if sim < rule.Detection.ThresholdLow {
			if rule.OnFail.Action == "block" {
				return 0, true, rule.OnFail.Reason, nil, nil
			}
			return 0, false, "", nil, nil
		} else if sim < rule.Detection.ThresholdHigh {
			return rule.Weight / 2, false, "", nil, nil
		}
		return rule.Weight, false, "", nil, nil
	case "function":
		fn, ok := e.funcMap[rule.Detection.Function]
		if !ok {
			return rule.Weight, false, "", nil, fmt.Errorf("function detector not found: %s", rule.Detection.Function)
		}
		return fn(skill, rule)
	case "forbid_pattern":
		return e.executeForbidPattern(skill, rule)
	case "require_pattern":
		return e.executeRequirePattern(skill, rule)
	case "code_vs_docs":
		return e.executeCodeVsDocs(skill, rule)
	case "artifact_vs_docs":
		return e.executeArtifactVsDocs(skill, rule)
	case "require_file_presence":
		return e.executeRequireFilePresence(skill, rule)
	case "ir_pattern":
		return e.executeIRPattern(skill, rule)
	default:
		return rule.Weight, false, "", nil, fmt.Errorf("unsupported detection type: %s", rule.Detection.Type)
	}
}

// executeForbidPattern 执行 forbid_pattern 类型规则：扫描文件中的禁用模式。
// 如果 include_globs 非空，只扫描匹配的文件；否则扫描所有文件。
// 当 pass_if == "no_match" 时，无匹配 = 通过，有匹配 = 失败（block）。
func (e *Evaluator) executeForbidPattern(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	compiledPatterns := e.patternMap[strings.TrimSpace(rule.ID)]
	if len(compiledPatterns) == 0 {
		// 没有可用模式，视为通过
		return rule.Weight, false, "", nil, nil
	}

	includeGlobs := rule.Detection.IncludeGlobs
	passIf := strings.TrimSpace(rule.Detection.PassIf)

	var details []FindingDetail
	for _, file := range skill.Files {
		// 如果指定了 include_globs，只扫描匹配的文件
		if len(includeGlobs) > 0 && !matchIncludeGlob(file.Path, includeGlobs) {
			continue
		}

		lines := strings.Split(file.AnalysisContent(), "\n")
		for lineNum, line := range lines {
			// 过滤注释行和行内注释
			codeLine := stripInlineComment(line)
			if codeLine == "" {
				continue
			}
			for _, re := range compiledPatterns {
				if re.MatchString(codeLine) {
					// 找到禁用模式
					loc := fmt.Sprintf("%s:%d", filepath.Base(file.Path), lineNum+1)
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    rule.Severity,
						Title:       rule.Name,
						Description: rule.Detection.Reason,
						Location:    loc,
						CodeSnippet: strings.TrimSpace(line),
					}
					details = append(details, detail)

					if passIf == "no_match" {
						// 有匹配 = 失败
						if rule.OnFail.Action == "block" {
							return 0, true, rule.OnFail.Reason, details, nil
						}
						return 0, false, rule.OnFail.Reason, details, nil
					}
				}
			}
		}
	}

	// 没有找到任何匹配
	if passIf == "no_match" {
		logx.With("component", "evaluator", "rule_id", rule.ID, "type", "forbid_pattern", "matched", false, "passed", true).Debug("detection result")
		return rule.Weight, false, "", nil, nil
	}
	logx.With("component", "evaluator", "rule_id", rule.ID, "type", "forbid_pattern", "matched", false, "passed", true).Debug("detection result")
	return rule.Weight, false, "", details, nil
}

// matchIncludeGlob 检查文件路径是否匹配 include_globs 中的任意一个。
// 支持 ** 递归匹配和 * 单层匹配。
func matchIncludeGlob(filePath string, globs []string) bool {
	for _, g := range globs {
		if matchSingleGlob(filePath, g) {
			return true
		}
	}
	return false
}

// matchSingleGlob 匹配单个 glob 模式，支持 ** 和 * 通配符。
func matchSingleGlob(filePath, pattern string) bool {
	// 将 glob 转换为正则
	var regexParts []string
	parts := strings.Split(pattern, "/")
	for i, part := range parts {
		if part == "**" {
			regexParts = append(regexParts, ".*")
		} else if part == "*" {
			regexParts = append(regexParts, "[^/]*")
		} else {
			// 转义其他字符，保留 * 通配符
			escaped := regexp.QuoteMeta(part)
			escaped = strings.ReplaceAll(escaped, "\\*", "[^/]*")
			regexParts = append(regexParts, escaped)
		}
		if i < len(parts)-1 {
			regexParts = append(regexParts, "/")
		}
	}
	regexStr := "^" + strings.Join(regexParts, "") + "$"
	re, err := regexp.Compile(regexStr)
	if err != nil {
		return false
	}
	return re.MatchString(filePath)
}

// executeRequirePattern 执行 require_pattern 类型规则：要求指定模式必须存在。
// 与 forbid_pattern 相反：有匹配 = 通过，无匹配 = 失败。
func (e *Evaluator) executeRequirePattern(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	compiledPatterns := e.patternMap[strings.TrimSpace(rule.ID)]
	if len(compiledPatterns) == 0 {
		return rule.Weight, false, "", nil, nil
	}

	includeGlobs := rule.Detection.IncludeGlobs
	found := false
	var details []FindingDetail

	for _, file := range skill.Files {
		if len(includeGlobs) > 0 && !matchIncludeGlob(file.Path, includeGlobs) {
			continue
		}
		lines := strings.Split(file.AnalysisContent(), "\n")
		for lineNum, line := range lines {
			// 过滤注释行和行内注释
			codeLine := stripInlineComment(line)
			if codeLine == "" {
				continue
			}
			for _, re := range compiledPatterns {
				if re.MatchString(codeLine) {
					found = true
					loc := fmt.Sprintf("%s:%d", filepath.Base(file.Path), lineNum+1)
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    rule.Severity,
						Title:       rule.Name,
						Description: rule.Detection.Reason,
						Location:    loc,
						CodeSnippet: strings.TrimSpace(line),
					}
					details = append(details, detail)
					break // 每行只需匹配一个模式
				}
			}
			if found {
				break // 找到即可停止
			}
		}
		if found {
			break
		}
	}

	if found {
		// 找到要求的模式 → 通过
		return rule.Weight, false, "", nil, nil
	}
	// 未找到 → 失败
	if rule.OnFail.Action == "block" {
		return 0, true, rule.OnFail.Reason, details, nil
	}
	return 0, false, rule.OnFail.Reason, details, nil
}

// executeCodeVsDocs 执行 code_vs_docs 类型规则：代码中发现高风险能力时，文档中必须有对应声明。
// 逻辑：扫描代码文件的 code_patterns → 如果命中，再扫描文档文件的 doc_patterns → 文档也命中则通过，否则失败。
func (e *Evaluator) executeCodeVsDocs(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	ruleID := strings.TrimSpace(rule.ID)
	codePatterns := e.codePatternMap[ruleID]
	docPatterns := e.docPatternMap[ruleID]

	// 如果没有代码模式，视为通过
	if len(codePatterns) == 0 {
		return rule.Weight, false, "", nil, nil
	}

	codeGlobs := rule.Detection.CodeIncludeGlobs
	docGlobs := rule.Detection.DocIncludeGlobs

	// 第一步：检查代码文件中是否有高风险模式
	var codeMatches []FindingDetail
	for _, file := range skill.Files {
		if len(codeGlobs) > 0 && !matchIncludeGlob(file.Path, codeGlobs) {
			continue
		}
		lines := strings.Split(file.AnalysisContent(), "\n")
		for lineNum, line := range lines {
			for _, re := range codePatterns {
				if re.MatchString(line) {
					loc := fmt.Sprintf("%s:%d", filepath.Base(file.Path), lineNum+1)
					codeMatches = append(codeMatches, FindingDetail{
						RuleID:      rule.ID,
						Severity:    rule.Severity,
						Title:       rule.Name,
						Description: "代码中发现高风险能力: " + re.String(),
						Location:    loc,
						CodeSnippet: strings.TrimSpace(line),
					})
					break
				}
			}
		}
	}

	// 没有高风险代码 → 通过
	if len(codeMatches) == 0 {
		return rule.Weight, false, "", nil, nil
	}

	// 第二步：检查文档中是否有声明
	if len(docPatterns) == 0 {
		// 没有文档模式可匹配，但有高风险代码 → 失败
		if rule.OnFail.Action == "block" {
			return 0, true, rule.OnFail.Reason, codeMatches, nil
		}
		return 0, false, rule.OnFail.Reason, codeMatches, nil
	}

	docDeclared := false
	for _, file := range skill.Files {
		if len(docGlobs) > 0 && !matchIncludeGlob(file.Path, docGlobs) {
			continue
		}
		content := file.AnalysisContent()
		for _, re := range docPatterns {
			if re.MatchString(content) {
				docDeclared = true
				break
			}
		}
		if docDeclared {
			break
		}
	}

	if docDeclared {
		// 文档中有声明 → 通过
		return rule.Weight, false, "", nil, nil
	}
	// 文档中没有声明 → 失败
	if rule.OnFail.Action == "block" {
		return 0, true, rule.OnFail.Reason, codeMatches, nil
	}
	return 0, false, rule.OnFail.Reason, codeMatches, nil
}

// executeArtifactVsDocs 执行 artifact_vs_docs 类型规则：发现预编译/二进制交付物时，文档中必须有声明。
// 逻辑：扫描制品文件的 artifact_patterns → 如果命中，再扫描文档的 doc_patterns → 文档也命中则通过，否则失败。
func (e *Evaluator) executeArtifactVsDocs(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	ruleID := strings.TrimSpace(rule.ID)
	artifactPatterns := e.artifactPatternMap[ruleID]
	docPatterns := e.docPatternMap[ruleID]

	if len(artifactPatterns) == 0 {
		return rule.Weight, false, "", nil, nil
	}

	artifactGlobs := rule.Detection.ArtifactIncludeGlobs
	docGlobs := rule.Detection.DocIncludeGlobs

	// 第一步：检查是否有预编译/二进制制品
	var artifactMatches []FindingDetail
	for _, file := range skill.Files {
		if len(artifactGlobs) > 0 && !matchIncludeGlob(file.Path, artifactGlobs) {
			continue
		}
		// 按文件路径匹配制品模式
		for _, re := range artifactPatterns {
			if re.MatchString(file.Path) {
				artifactMatches = append(artifactMatches, FindingDetail{
					RuleID:      rule.ID,
					Severity:    rule.Severity,
					Title:       rule.Name,
					Description: "发现预编译/二进制交付物: " + file.Path,
					Location:    file.Path,
					CodeSnippet: file.Path,
				})
				break
			}
		}
	}

	// 没有制品 → 通过
	if len(artifactMatches) == 0 {
		return rule.Weight, false, "", nil, nil
	}

	// 第二步：检查文档中是否有声明
	if len(docPatterns) == 0 {
		if rule.OnFail.Action == "block" {
			return 0, true, rule.OnFail.Reason, artifactMatches, nil
		}
		return 0, false, rule.OnFail.Reason, artifactMatches, nil
	}

	docDeclared := false
	for _, file := range skill.Files {
		if len(docGlobs) > 0 && !matchIncludeGlob(file.Path, docGlobs) {
			continue
		}
		content := file.AnalysisContent()
		for _, re := range docPatterns {
			if re.MatchString(content) {
				docDeclared = true
				break
			}
		}
		if docDeclared {
			break
		}
	}

	if docDeclared {
		return rule.Weight, false, "", nil, nil
	}
	if rule.OnFail.Action == "block" {
		return 0, true, rule.OnFail.Reason, artifactMatches, nil
	}
	return 0, false, rule.OnFail.Reason, artifactMatches, nil
}

// executeRequireFilePresence 执行 require_file_presence 类型规则：要求指定文件必须存在。
// 检查文件路径中是否匹配 required_files 或 patterns。
func (e *Evaluator) executeRequireFilePresence(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	requiredFiles := rule.Detection.RequiredFiles
	compiledPatterns := e.patternMap[strings.TrimSpace(rule.ID)]

	found := false
	var details []FindingDetail

	for _, file := range skill.Files {
		filePath := file.Path
		fileBase := filepath.Base(filePath)

		// 检查 required_files 列表
		for _, req := range requiredFiles {
			if strings.Contains(filePath, req) || strings.EqualFold(fileBase, req) {
				found = true
				details = append(details, FindingDetail{
					RuleID:      rule.ID,
					Severity:    rule.Severity,
					Title:       rule.Name,
					Description: rule.Detection.Reason,
					Location:    filePath,
					CodeSnippet: filePath,
				})
				break
			}
		}
		if found {
			break
		}

		// 检查 patterns（匹配文件路径）
		for _, re := range compiledPatterns {
			if re.MatchString(filePath) || re.MatchString(fileBase) {
				found = true
				details = append(details, FindingDetail{
					RuleID:      rule.ID,
					Severity:    rule.Severity,
					Title:       rule.Name,
					Description: rule.Detection.Reason,
					Location:    filePath,
					CodeSnippet: filePath,
				})
				break
			}
		}
		if found {
			break
		}
	}

	if found {
		return rule.Weight, false, "", nil, nil
	}
	if rule.OnFail.Action == "block" {
		return 0, true, rule.OnFail.Reason, details, nil
	}
	return 0, false, rule.OnFail.Reason, details, nil
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
	risk.Title = strings.TrimSpace(risk.Title)
	risk.Severity = strings.ToLower(strings.TrimSpace(risk.Severity))
	risk.Status = normalizeLLMRiskStatus(risk.Status)
	risk.Confidence = normalizeLLMScale(risk.Confidence, "medium")
	risk.Exploitability = normalizeLLMExploitability(risk.Exploitability)
	risk.Description = strings.TrimSpace(risk.Description)
	risk.Evidence = strings.TrimSpace(risk.Evidence)
	risk.KeyCodeLocation = strings.TrimSpace(risk.KeyCodeLocation)
	risk.Remediation = strings.TrimSpace(risk.Remediation)
	risk.VerificationStep = strings.TrimSpace(risk.VerificationStep)
	risk.RemediationQuality = normalizeLLMScale(risk.RemediationQuality, "medium")
	text := strings.ToLower(strings.TrimSpace(risk.Title + " " + risk.Description + " " + risk.Evidence))
	if isLicenseConfigRisk(text) {
		risk.Title = "授权绕过风险 - 许可证校验逻辑不闭环"
	}
	if strings.Contains(text, "break-system-packages") || strings.Contains(text, "pep 668") {
		risk.Title = "Python 环境隔离被绕过"
	}
	return risk
}

func shouldSkipLLMRisk(risk llm.RiskItem) bool {
	text := strings.ToLower(strings.TrimSpace(risk.Title + " " + risk.Description + " " + risk.Evidence + " " + strings.Join(risk.EvidenceRefs, " ")))
	if risk.Status == "dismissed" || strings.TrimSpace(risk.Title+risk.Description+risk.Evidence) == "" {
		return true
	}
	if isLowSignalNarrativeText(text) {
		return true
	}
	return false
}

func calibrateLLMRisk(risk llm.RiskItem, loc, snippet string) llm.RiskItem {
	if risk.Status == "" {
		risk.Status = "confirmed"
	}
	if strings.TrimSpace(loc) == "" || strings.TrimSpace(snippet+risk.Evidence) == "" {
		risk.Status = "needs-review"
		if risk.Confidence == "high" {
			risk.Confidence = "medium"
		}
	}
	if risk.RiskScore <= 0 {
		risk.RiskScore = computeLLMRiskScore(risk)
	}
	if len(risk.EvidenceRefs) == 0 {
		risk.EvidenceRefs = []string{defaultText(loc, "LLM evidence")}
	}
	if risk.Remediation == "" || isGenericRemediation(risk.Remediation) {
		risk.Remediation = buildEvidenceBoundRemediation(risk, loc)
		risk.RemediationQuality = "medium"
	}
	if risk.VerificationStep == "" || isGenericRemediation(risk.VerificationStep) {
		risk.VerificationStep = buildLLMVerificationStep(risk, loc)
	}
	if remediationQualityLow(risk, loc) {
		risk.RemediationQuality = "low"
	} else if risk.RemediationQuality == "" || risk.RemediationQuality == "medium" {
		risk.RemediationQuality = "high"
	}
	return risk
}

func normalizeLLMRiskStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "confirmed", "确认", "已确认":
		return "confirmed"
	case "needs-review", "needs_review", "review", "需复核", "待复核":
		return "needs-review"
	case "dismissed", "false-positive", "false_positive", "误报", "忽略":
		return "dismissed"
	default:
		return ""
	}
}

func normalizeLLMScale(value, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high", "高", "高风险":
		return "high"
	case "medium", "中", "中风险":
		return "medium"
	case "low", "低", "低风险":
		return "low"
	default:
		return fallback
	}
}

func normalizeLLMExploitability(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high", "高":
		return "high"
	case "medium", "中":
		return "medium"
	case "low", "低":
		return "low"
	case "unknown", "未知", "":
		return "unknown"
	default:
		return "unknown"
	}
}

func computeLLMRiskScore(risk llm.RiskItem) int {
	score := 20
	switch risk.Severity {
	case "high", "critical":
		score += 35
	case "medium":
		score += 20
	case "low":
		score += 10
	}
	switch risk.Confidence {
	case "high":
		score += 20
	case "medium":
		score += 10
	}
	switch risk.Exploitability {
	case "high":
		score += 20
	case "medium":
		score += 10
	case "low":
		score += 5
	}
	text := strings.ToLower(risk.Title + " " + risk.Description + " " + risk.Evidence)
	if containsAny(text, "token", "secret", "password", "private key", "凭据", "密钥", "令牌", "反弹 shell", "reverse shell", "persistence", "持久化") {
		score += 10
	}
	if score > 100 {
		return 100
	}
	return score
}

func isGenericRemediation(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return true
	}
	return containsAny(lower,
		"follow best practices", "security best practices", "validate input", "sanitize input", "加强安全", "做好校验", "进行安全加固", "遵循最佳实践", "注意安全", "建议修复", "加强防护", "复测", "重新测试",
	)
}

func buildEvidenceBoundRemediation(risk llm.RiskItem, loc string) string {
	location := defaultText(loc, risk.KeyCodeLocation)
	behavior := defaultText(risk.Description, risk.Title)
	return fmt.Sprintf("在 %s 修改与该风险相关的代码路径：%s。移除或收敛触发风险的行为，使实现只保留声明范围内的必要能力；如果确需保留该能力，需要增加明确声明、最小权限边界和失败即拒绝的处理。", defaultText(location, "对应证据位置"), behavior)
}

func buildLLMVerificationStep(risk llm.RiskItem, loc string) string {
	location := defaultText(loc, risk.KeyCodeLocation)
	return fmt.Sprintf("修复后重新扫描并检查 %s 对应证据，确认原风险行为消失，且报告中该 finding 变为 resolved 或不再出现 confirmed 风险。", defaultText(location, "原风险位置"))
}

func remediationQualityLow(risk llm.RiskItem, loc string) bool {
	if strings.TrimSpace(risk.Remediation) == "" || strings.TrimSpace(risk.VerificationStep) == "" {
		return true
	}
	if isGenericRemediation(risk.Remediation) {
		return true
	}
	joined := strings.ToLower(risk.Remediation + " " + risk.VerificationStep)
	return strings.TrimSpace(loc) != "" && !strings.Contains(joined, strings.ToLower(strings.Split(loc, ":")[0])) && !containsAny(joined, "证据", "风险", "声明", "行为", "重新扫描", "复测")
}

func formatLLMRiskDescription(risk llm.RiskItem) string {
	parts := []string{defaultText(risk.Description, risk.Title)}
	parts = append(parts,
		"确认状态: "+defaultText(risk.Status, "confirmed"),
		"置信度: "+defaultText(risk.Confidence, "medium"),
		"可利用性: "+defaultText(risk.Exploitability, "unknown"),
		fmt.Sprintf("风险分: %d", risk.RiskScore),
	)
	if risk.RemediationQuality != "" {
		parts = append(parts, "修复建议质量: "+risk.RemediationQuality)
	}
	if risk.Remediation != "" {
		parts = append(parts, "修复建议: "+risk.Remediation)
	}
	if risk.VerificationStep != "" {
		parts = append(parts, "验证步骤: "+risk.VerificationStep)
	}
	return strings.Join(parts, "\n")
}

func formatLLMRiskSnippet(risk llm.RiskItem, snippet string) string {
	parts := make([]string, 0, 4)
	if strings.TrimSpace(snippet) != "" {
		parts = append(parts, strings.TrimSpace(snippet))
	}
	if strings.TrimSpace(risk.Evidence) != "" && !strings.Contains(strings.Join(parts, "\n"), strings.TrimSpace(risk.Evidence)) {
		parts = append(parts, "LLM证据: "+strings.TrimSpace(risk.Evidence))
	}
	if len(risk.EvidenceRefs) > 0 {
		parts = append(parts, "证据引用: "+strings.Join(risk.EvidenceRefs, "；"))
	}
	return strings.Join(parts, "\n")
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
	ttl := time.Duration(config.EvaluatorCacheTTLSecs()) * time.Second
	if ttl <= 0 {
		ttl = defaultEvaluatorCacheTTL
	}
	e.cache.Add(key, CacheItem{Result: result, ExpireAt: time.Now().Add(ttl)})
}

func (e *Evaluator) getCachedResult(key string) (CacheItem, bool) {
	e.cacheMutex.RLock()
	item, ok := e.cache.Get(key)
	e.cacheMutex.RUnlock()
	if !ok {
		return CacheItem{}, false
	}
	if item.ExpireAt.After(time.Now()) {
		return item, true
	}
	e.cacheMutex.Lock()
	e.cache.Remove(key)
	e.cacheMutex.Unlock()
	return CacheItem{}, false
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
	risk := e.assessDependencyRisk(context.Background(), skill)
	return clampScore(20.0-risk.ScoreDeduction, 0, 20)
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
			if shouldSkipExecutableSignalLine(trimmed) {
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
	suspiciousPayloadFound := false
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
		if !suspiciousPayloadFound && hasSuspiciousEncodedPayload(code) {
			suspiciousPayloadFound = true
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
	if base64Count >= 2 && suspiciousPayloadFound {
		score -= 3
	}
	if highEntropyFound && suspiciousPayloadFound {
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
	risk := assessResourceRisk(skill)
	return clampScore(5.0-risk.ScoreDeduction, 0, 5)
}

type dependencyRiskAssessment struct {
	ScoreDeduction float64
	Findings       []FindingDetail
	Warnings       []string
}

type resourceRiskAssessment struct {
	ScoreDeduction float64
	Findings       []FindingDetail
}

func (e *Evaluator) assessDependencyRisk(ctx context.Context, skill *Skill) dependencyRiskAssessment {
	if skill == nil {
		return dependencyRiskAssessment{}
	}
	knownMalicious := map[string]string{
		"ctx":               "命中已知恶意 npm 包名 `ctx`，历史上常被用于投毒或伪装正常组件。",
		"crossenv":          "命中已知恶意 npm 包名 `crossenv`，与 `cross-env` 仅一字符差异。",
		"nodejs_net_server": "命中已知恶意 npm 包名 `nodejs_net_server`，存在投毒历史。",
		"pymafka":           "命中已知恶意 PyPI 包名 `pymafka`，为投毒样本。",
		"jeilyfish":         "命中已知恶意 PyPI 包名 `jeilyfish`，为拼写劫持样本。",
		"colourama":         "命中已知恶意 PyPI 包名 `colourama`，与 `colorama` 高相似。",
	}
	trustedTargets := []string{"requests", "flask", "django", "numpy", "pandas", "axios", "lodash", "react", "express", "cross-env", "colorama", "torch", "fastapi", "gin", "gorm", "testify", "yaml.v3", "uuid"}
	seen := map[string]struct{}{}
	findings := make([]FindingDetail, 0)
	totalPenalty := 0.0
	add := func(key string, detail FindingDetail, penalty float64) {
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		findings = append(findings, detail)
		totalPenalty += penalty
	}
	for _, dep := range skill.Dependencies {
		name := strings.TrimSpace(dep.Name)
		version := strings.TrimSpace(dep.Version)
		if name == "" {
			continue
		}
		canonical := canonicalDependencyName(name)
		location := dependencyLocationLabel(name, version)
		if reason, ok := knownMalicious[canonical]; ok {
			add(name+"|malicious", FindingDetail{
				Severity:    "高风险",
				Description: reason,
				Location:    location,
				CodeSnippet: fmt.Sprintf("dependency=%s version=%s", name, defaultText(version, "<unknown>")),
			}, 12)
			continue
		}
		if target, dist, ok := detectTyposquatPackage(canonical, trustedTargets); ok {
			add(name+"|typosquat", FindingDetail{
				Severity:    "中风险",
				Description: fmt.Sprintf("依赖名 `%s` 与常见官方包 `%s` 高相似（编辑距离=%d），疑似拼写劫持或混淆包。", name, target, dist),
				Location:    location,
				CodeSnippet: fmt.Sprintf("dependency=%s version=%s", name, defaultText(version, "<unknown>")),
			}, 8)
		}
		if dependencyVersionUncertain(version) {
			add(name+"|version", FindingDetail{
				Severity:    "中风险",
				Description: fmt.Sprintf("依赖 `%s` 未锁定到稳定版本，存在自动引入漏洞或恶意更新的风险。", name),
				Location:    location,
				CodeSnippet: fmt.Sprintf("dependency=%s version=%s", name, defaultText(version, "<unknown>")),
			}, 4)
		}
		if strings.HasPrefix(strings.ToLower(version), "0.") {
			add(name+"|zero-major", FindingDetail{
				Severity:    "低风险",
				Description: fmt.Sprintf("依赖 `%s` 使用 0.x 版本，API 和安全基线通常仍不稳定，建议确认是否必须保留。", name),
				Location:    location,
				CodeSnippet: fmt.Sprintf("dependency=%s version=%s", name, version),
			}, 2)
		}
	}
	osvAssessment := e.assessDependencyRiskWithOSV(ctx, skill)
	for _, finding := range osvAssessment.Findings {
		add("osv|"+finding.Location+"|"+finding.CodeSnippet, finding, 6)
	}
	return dependencyRiskAssessment{ScoreDeduction: minFloat64(20, totalPenalty), Findings: findings, Warnings: osvAssessment.Warnings}
}

func (e *Evaluator) assessDependencyRiskWithOSV(ctx context.Context, skill *Skill) dependencyRiskAssessment {
	if e == nil || e.osvClient == nil || skill == nil {
		return dependencyRiskAssessment{}
	}
	queries, indexes := buildOSVQueries(skill.Dependencies)
	if len(queries) == 0 {
		return dependencyRiskAssessment{}
	}
	results, err := e.osvClient.QueryBatch(ctx, queries)
	if err != nil {
		return dependencyRiskAssessment{Warnings: []string{"OSV 漏洞查询暂时不可用，已降级为本地依赖风险评估。"}}
	}
	findings := make([]FindingDetail, 0)
	seen := map[string]struct{}{}
	for i, result := range results {
		if i >= len(indexes) || len(result.Vulns) == 0 {
			continue
		}
		dep := indexes[i]
		location := dependencyLocationLabel(dep.Name, dep.Version)
		for _, vuln := range result.Vulns {
			id := strings.TrimSpace(vuln.ID)
			if id == "" {
				continue
			}
			key := dep.Name + "|" + dep.Version + "|" + id
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			desc := strings.TrimSpace(vuln.Summary)
			if desc == "" {
				desc = fmt.Sprintf("依赖 `%s`@`%s` 命中 OSV 漏洞 `%s`。", dep.Name, dep.Version, id)
			} else {
				desc = fmt.Sprintf("依赖 `%s`@`%s` 命中 OSV 漏洞 `%s`：%s", dep.Name, dep.Version, id, desc)
			}
			findings = append(findings, FindingDetail{
				RuleID:      "V7-010-OSV",
				Severity:    "高风险",
				Title:       "依赖漏洞与供应链风险",
				Description: desc,
				Location:    location,
				CodeSnippet: fmt.Sprintf("OSV 证据: dependency=%s version=%s vuln=%s", dep.Name, dep.Version, id),
			})
		}
	}
	return dependencyRiskAssessment{Findings: findings}
}

func buildOSVQueries(deps []Dependency) ([]osvPackageQuery, []Dependency) {
	queries := make([]osvPackageQuery, 0, len(deps))
	indexes := make([]Dependency, 0, len(deps))
	for _, dep := range deps {
		name := strings.TrimSpace(dep.Name)
		version := normalizeDependencyVersionForOSV(dep.Version)
		ecosystem := detectOSVEcosystem(name)
		if name == "" || version == "" || ecosystem == "" {
			continue
		}
		queries = append(queries, osvPackageQuery{Name: name, Version: version, Ecosystem: ecosystem})
		indexes = append(indexes, dep)
	}
	return queries, indexes
}

func normalizeDependencyVersionForOSV(version string) string {
	v := strings.TrimSpace(version)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimPrefix(v, ">=")
	v = strings.TrimPrefix(v, "<=")
	v = strings.TrimPrefix(v, ">")
	v = strings.TrimPrefix(v, "<")
	v = strings.TrimPrefix(v, "=")
	v = strings.TrimSpace(v)
	if v == "" || dependencyVersionUncertain(v) || strings.ContainsAny(v, "*x| ") {
		return ""
	}
	return v
}

func detectOSVEcosystem(name string) string {
	trimmed := strings.TrimSpace(name)
	lower := strings.ToLower(trimmed)
	switch {
	case strings.HasPrefix(trimmed, "github.com/") || strings.HasPrefix(trimmed, "golang.org/") || strings.HasPrefix(trimmed, "gopkg.in/"):
		return "Go"
	case strings.HasPrefix(trimmed, "@") || strings.Contains(lower, "react") || strings.Contains(lower, "lodash") || strings.Contains(lower, "axios") || strings.Contains(lower, "express"):
		return "npm"
	case regexp.MustCompile(`^[a-z0-9_.-]+$`).MatchString(lower):
		return "PyPI"
	default:
		return ""
	}
}

func reviewPolicyConfig() *config.ReviewPolicyConfig {
	cfg, err := config.DefaultReviewPolicy()
	if err != nil {
		return nil
	}
	return cfg
}

func assessResourceRisk(skill *Skill) resourceRiskAssessment {
	if skill == nil {
		return resourceRiskAssessment{}
	}
	patterns := config.ReviewResourceRiskPatterns{
		Loop:         `(?i)^for\s*\{\s*$|^while\s*\(?\s*true\s*\)?\s*[:{]?$|for\s*\(\s*;\s*;\s*\)`,
		Goroutine:    `(?i)\bgo\s+[A-Za-z_][A-Za-z0-9_]*\(|asyncio\.create_task\(|threading\.thread\(|executor\.submit\(|promise\.all\(`,
		Retry:        `(?i)(retry|backoff|attempt|tries|retries)`,
		Network:      `(?i)(http\.get\(|http\.post\(|http\.newrequest\(|requests\.(get|post)\(|fetch\(|axios\.(get|post)|client\.do\()`,
		TimeoutGuard: `(?i)(timeout|deadline|context\.withtimeout|context\.withdeadline|client\.timeout|setdefaulttimeout)`,
		BackoffGuard: `(?i)(sleep\(|time\.sleep\(|await asyncio\.sleep\(|backoff|exponential|jitter)`,
	}
	if cfg := reviewPolicyConfig(); cfg != nil {
		patterns = cfg.EffectiveResourceRiskPatterns(patterns)
	}
	loopRe := regexp.MustCompile(patterns.Loop)
	goRoutineRe := regexp.MustCompile(patterns.Goroutine)
	retryRe := regexp.MustCompile(patterns.Retry)
	networkRe := regexp.MustCompile(patterns.Network)
	timeoutGuardRe := regexp.MustCompile(patterns.TimeoutGuard)
	backoffGuardRe := regexp.MustCompile(patterns.BackoffGuard)
	recursionDefRe := regexp.MustCompile(`(?i)^(?:func|def)\s+([A-Za-z_][A-Za-z0-9_]*)`)
	findings := make([]FindingDetail, 0)
	seen := map[string]struct{}{}
	penalty := 0.0
	add := func(key string, detail FindingDetail, delta float64) {
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		findings = append(findings, detail)
		penalty += delta
	}
	for _, file := range skill.Files {
		if isLowSignalExamplePath(file.Path) {
			continue
		}
		lines := strings.Split(file.AnalysisContent(), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if shouldSkipSemanticLine(trimmed) {
				continue
			}
			lower := strings.ToLower(trimmed)
			if loopRe.MatchString(trimmed) {
				add(file.Path+":loop", FindingDetail{
					Severity:    "中风险",
					Description: "检测到无退出条件循环，存在 CPU 持续占用和任务阻塞风险。",
					Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
					CodeSnippet: formatCodeContext(lines, i, 2),
				}, 5)
			}
			if networkRe.MatchString(lower) {
				window := strings.ToLower(joinNearbyLines(lines, i, 3))
				if !timeoutGuardRe.MatchString(window) {
					add(file.Path+fmt.Sprintf(":net:%d", i), FindingDetail{
						Severity:    "低风险",
						Description: "检测到网络请求缺少显式超时控制，下游故障时可能造成线程堆积或任务悬挂。",
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}, 2)
				}
			}
			if retryRe.MatchString(lower) && networkRe.MatchString(strings.ToLower(joinNearbyLines(lines, i, 4))) && !backoffGuardRe.MatchString(strings.ToLower(joinNearbyLines(lines, i, 4))) {
				add(file.Path+fmt.Sprintf(":retry:%d", i), FindingDetail{
					Severity:    "中风险",
					Description: "检测到重试语义与外部调用相邻出现，但未识别到退避、抖动或上限控制，可能形成重试风暴。",
					Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
					CodeSnippet: formatCodeContext(lines, i, 3),
				}, 3)
			}
			if goRoutineRe.MatchString(trimmed) {
				window := strings.ToLower(joinNearbyLines(lines, i, 4))
				if !strings.Contains(window, "worker") && !strings.Contains(window, "limit") && !strings.Contains(window, "semaphore") {
					add(file.Path+fmt.Sprintf(":goroutine:%d", i), FindingDetail{
						Severity:    "中风险",
						Description: "检测到并发任务创建语句，但未识别到工作池、信号量或并发上限控制。",
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 3),
					}, 3)
				}
			}
			if def := recursionDefRe.FindStringSubmatch(trimmed); len(def) == 2 {
				name := def[1]
				callRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\(`)
				start := i + 1
				if start >= len(lines) {
					continue
				}
				end := start + 8
				if end > len(lines) {
					end = len(lines)
				}
				window := strings.Join(lines[start:end], "\n")
				lowerWindow := strings.ToLower(window)
				if callRe.MatchString(window) && !strings.Contains(lowerWindow, "maxdepth") && !strings.Contains(lowerWindow, "depth ") && !strings.Contains(lowerWindow, "depth=") {
					add(file.Path+":recursion:"+name, FindingDetail{
						Severity:    "低风险",
						Description: fmt.Sprintf("检测到函数 `%s` 递归调用，但附近未识别到明显的深度/终止边界控制。", name),
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 8),
					}, 2)
				}
			}
		}
	}
	return resourceRiskAssessment{ScoreDeduction: minFloat64(5, penalty), Findings: findings}
}

func canonicalDependencyName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	lower = strings.TrimPrefix(lower, "github.com/")
	lower = strings.TrimPrefix(lower, "gitlab.com/")
	lower = strings.TrimPrefix(lower, "gopkg.in/")
	lower = strings.TrimPrefix(lower, "@")
	parts := strings.FieldsFunc(lower, func(r rune) bool {
		switch r {
		case '/', ':', '#':
			return true
		default:
			return false
		}
	})
	if len(parts) == 0 {
		return lower
	}
	return strings.TrimSuffix(parts[len(parts)-1], ".git")
}

func detectTyposquatPackage(candidate string, trusted []string) (string, int, bool) {
	if candidate == "" {
		return "", 0, false
	}
	for _, item := range trusted {
		canonical := canonicalDependencyName(item)
		if canonical == candidate {
			return "", 0, false
		}
		dist := editDistanceASCII(candidate, canonical)
		if dist == 1 && absInt(len(candidate)-len(canonical)) <= 1 {
			return item, dist, true
		}
		if dist == 2 && len(candidate) >= 8 && absInt(len(candidate)-len(canonical)) <= 1 {
			return item, dist, true
		}
	}
	return "", 0, false
}

func dependencyLocationLabel(name, version string) string {
	if strings.TrimSpace(version) == "" {
		return fmt.Sprintf("dependency:%s", name)
	}
	return fmt.Sprintf("dependency:%s@%s", name, version)
}

func editDistanceASCII(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr := make([]int, len(b)+1)
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			curr[j] = minInt3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev = curr
	}
	return prev[len(b)]
}

func minInt3(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func minFloat64(a, b float64) float64 {
	if a <= b {
		return a
	}
	return b
}

func clampScore(value, minValue, maxValue float64) float64 {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
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
	files = prioritizeLLMIntentFiles(files)
	var summary strings.Builder
	for _, file := range files {
		if summary.Len() >= maxLLMIntentSummaryBytes {
			break
		}
		fileSummary := strings.TrimSpace(extractCodeSummary(file.AnalysisContent()))
		if fileSummary == "" {
			continue
		}
		fileSummary = fmt.Sprintf("[%s %s] %s", filepath.Base(file.Path), strings.TrimSpace(file.Language), fileSummary)
		if len(fileSummary) > maxLLMIntentSummaryBytesPerFile {
			fileSummary = truncateStringBytes(fileSummary, maxLLMIntentSummaryBytesPerFile)
		}
		remaining := maxLLMIntentSummaryBytes - summary.Len()
		if remaining <= 0 {
			break
		}
		if len(fileSummary) > remaining {
			fileSummary = truncateStringBytes(fileSummary, remaining)
		}
		summary.WriteString(fileSummary)
		if summary.Len() < maxLLMIntentSummaryBytes {
			summary.WriteString(" ")
		}
	}
	return summary.String()
}

func prioritizeLLMIntentFiles(files []SourceFile) []SourceFile {
	out := append([]SourceFile{}, files...)
	sort.SliceStable(out, func(i, j int) bool {
		return llmIntentFilePriority(out[i]) < llmIntentFilePriority(out[j])
	})
	return out
}

func llmIntentFilePriority(file SourceFile) int {
	base := strings.ToLower(filepath.Base(file.Path))
	switch base {
	case "skill.md", "readme.md", "description.md", "manifest.md", "package.json", "go.mod", "pyproject.toml", "requirements.txt":
		return 0
	}
	ext := strings.ToLower(filepath.Ext(file.Path))
	switch ext {
	case ".go", ".js", ".ts", ".py":
		return 1
	case ".md", ".json", ".yaml", ".yml", ".toml":
		return 2
	default:
		return 3
	}
}

func truncateStringBytes(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	end := 0
	for i := range value {
		if i > limit {
			break
		}
		end = i
	}
	if end == 0 {
		return ""
	}
	return value[:end]
}

func formatLLMIntentError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Sprintf("LLM 请求超时（当前超时 %d 秒）。请检查模型响应速度、网络连通性，或通过 REVIEW_LLM_REQUEST_TIMEOUT_SECS 调大超时时间", config.LLMRequestTimeoutSecs())
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Sprintf("LLM 请求超时（当前超时 %d 秒）。请检查模型响应速度、网络连通性，或通过 REVIEW_LLM_REQUEST_TIMEOUT_SECS 调大超时时间", config.LLMRequestTimeoutSecs())
	}
	return err.Error()
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
func (e *Evaluator) detectHardcodedCredentialFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
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
			return 0, true, rule.OnFail.Reason, details, nil
		}
		return 0, false, "", details, nil
	}
	return rule.Weight, false, "", nil, nil
}

func (e *Evaluator) detectDataExfiltrationFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	var details []FindingDetail
	networkCallRe := regexp.MustCompile(`(?i)(requests\.(post|get|put|request)\(|fetch\(|axios\.(post|get|put|request)\(|http\.post\(|client\.do\(|send\()`) 
	highRiskSourceRe := regexp.MustCompile(`(?i)(process\.env|os\.getenv|getenv\(|authorization|bearer|cookie|token|secret|api[_-]?key|oem_api_key|/etc/passwd|~/.ssh|\.env\b)`) 
	webhookLikeRe := regexp.MustCompile(`(?i)(webhook|callback|beacon|upload|report)`) 
	userControlledTargetRe := regexp.MustCompile(`(?i)(requests\.(post|get|put|request)\((target|url|endpoint|upload_url)|fetch\((target|url|endpoint|upload_url)|axios\.(post|get|put|request)\((target|url|endpoint|upload_url))`) 
	dnsExfilRe := regexp.MustCompile(`(?i)nslookup.*attacker\.com`)
	encodedExfilRe := regexp.MustCompile(`(?i)btoa.*json\.stringify.*fetch`)
	for _, file := range skill.Files {
		lines := strings.Split(file.Content, "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if shouldSkipSemanticLine(trimmed) || isLikelyLogOnlyLine(trimmed) {
				continue
			}
			if dnsExfilRe.MatchString(trimmed) {
				details = append(details, FindingDetail{RuleID: rule.ID, Severity: "高风险", Title: rule.Name, Description: rule.OnFail.Reason + ": 检测到 DNS 外带数据语义", Location: fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1), CodeSnippet: formatCodeContext(lines, i, 2)})
				continue
			}
			if encodedExfilRe.MatchString(trimmed) {
				details = append(details, FindingDetail{RuleID: rule.ID, Severity: "高风险", Title: rule.Name, Description: rule.OnFail.Reason + ": 检测到编码后外发语义", Location: fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1), CodeSnippet: formatCodeContext(lines, i, 2)})
				continue
			}
			if !networkCallRe.MatchString(trimmed) {
				continue
			}
			severity := ""
			desc := ""
			switch {
			case highRiskSourceRe.MatchString(trimmed):
				severity = "高风险"
				desc = "检测到高敏感字段或凭据随外联动作离开当前执行边界"
			case userControlledTargetRe.MatchString(trimmed):
				severity = "中风险"
				desc = "检测到用户可控外联目标，需确认 allowlist、鉴权和字段范围"
			case webhookLikeRe.MatchString(trimmed):
				severity = "中风险"
				desc = "检测到 webhook/callback/report 外联回传语义，需确认声明覆盖、授权边界和字段范围"
			default:
				continue
			}
				details = append(details, FindingDetail{
					RuleID:      rule.ID,
					Severity:    severity,
					Title:       rule.Name,
					Description: desc,
					Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
					CodeSnippet: formatCodeContext(lines, i, 2),
				})
		}
	}
	if len(details) > 0 {
		blocked := false
		for _, detail := range details {
			if detail.Severity == "高风险" {
				blocked = rule.OnFail.Action == "block"
				break
			}
		}
		if blocked {
			return 0, true, rule.OnFail.Reason, details, nil
		}
		return rule.Weight * 0.4, false, "", details, nil
	}
	return rule.Weight, false, "", nil, nil
}

func (e *Evaluator) detectMCPAbuseFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
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
			return 0, true, rule.OnFail.Reason, details, nil
		}
		return 0, false, "", details, nil
	}
	return rule.Weight, false, "", nil, nil
}

func (e *Evaluator) detectEnvironmentEvasionFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
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
		return rule.Weight, false, "", nil, nil
	}
	if rule.OnFail.Action == "block" {
		return 0, true, rule.OnFail.Reason, details, nil
	}
	return 0, false, "", details, nil
}

func (e *Evaluator) evaluateIrreversibleOpsApprovalFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
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
		return rule.Weight, false, "", nil, nil
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
		return rule.Weight, false, "", nil, nil
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
		return 0, true, rule.OnFail.Reason, []FindingDetail{detail}, nil
	}
	return 0, false, "", []FindingDetail{detail}, nil
}

func (e *Evaluator) evaluateDataMinimizationEvidenceFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	declared, declaredEvidence := collectSensitiveSignals(skill.Description, "技能声明", false, false)
	actual := make([]string, 0)
	actualEvidenceByLabel := make(map[string]signalEvidence)
	for _, file := range skill.Files {
		labels, evidences := collectSensitiveSignals(file.AnalysisContent(), filepath.Base(file.Path), true, isProductionSourceFile(file.Path))
		actual = append(actual, labels...)
		for _, ev := range evidences {
			if shouldSuppressSensitiveSignal(ev) {
				continue
			}
			if prev, ok := actualEvidenceByLabel[ev.Label]; !ok || sensitiveActionRank(ev.Action) > sensitiveActionRank(prev.Action) {
				actualEvidenceByLabel[ev.Label] = ev
			}
		}
	}
	actual = uniqueStrings(actual)
	actual = filterSensitiveLabelsByEvidence(actual, actualEvidenceByLabel)

	if len(declared) == 0 && len(actual) == 0 {
		return rule.Weight, false, "", nil, nil
	}

	extra := diffStrings(actual, declared)
	desc := fmt.Sprintf("技能声明收集的数据：%s\n技能实际收集的数据：%s", joinOrFallback(declared), joinOrFallback(actual))
	severity := "低风险"
	score := rule.Weight
	if len(extra) > 0 {
		severity = "中风险"
		actionSummary := summarizeSensitiveActions(extra, actualEvidenceByLabel)
		if actionSummary != "" {
			desc += "\n动作摘要：" + actionSummary
		}
		desc += fmt.Sprintf("\n检测到声明外数据收集：%s", strings.Join(extra, "、"))
		score = rule.Weight * 0.4
		escalation := classifySensitiveCollectionEscalation(extra, actualEvidenceByLabel)
		switch escalation {
		case "high":
			severity = "高风险"
			score = rule.Weight * 0.2
			desc += "\n检测到高敏感字段经外发动作离开当前执行边界，需优先收敛字段和目标范围。"
		case "medium-external":
			desc += "\n检测到会话或联系方式经外发动作离开当前执行边界，需确认字段必要性、目标范围和授权边界。"
		case "medium-storage":
			desc += "\n检测到会话或联系方式被写入日志或持久化存储，需确认脱敏、保留周期和用途边界。"
		}
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
			actionText := ""
			if ev.Action != "" {
				actionText = fmt.Sprintf("（动作=%s）", ev.Action)
			}
			details = append(details, FindingDetail{
				RuleID:      rule.ID,
				Severity:    "中风险",
				Title:       rule.Name,
				Description: fmt.Sprintf("检测到声明外数据收集类型：%s%s", label, actionText),
				Location:    defaultEvidenceLocation(ev.Location),
				CodeSnippet: fmt.Sprintf("命中数据类型: %s\n关键证据:\n%s", label, defaultEvidenceSnippet(ev.Snippet)),
			})
		}
		return score, false, "", details, nil
	}
	return rule.Weight, false, "", details, nil
}

func summarizeSensitiveActions(labels []string, evidenceByLabel map[string]signalEvidence) string {
	parts := make([]string, 0, len(labels))
	for _, label := range labels {
		ev, ok := evidenceByLabel[label]
		if !ok || strings.TrimSpace(ev.Action) == "" {
			continue
		}
		parts = append(parts, label+"="+ev.Action)
	}
	return strings.Join(uniqueStrings(parts), "；")
}

func classifySensitiveCollectionEscalation(labels []string, evidenceByLabel map[string]signalEvidence) string {
	hasMediumExternal := false
	hasMediumStorage := false
	for _, label := range labels {
		ev, ok := evidenceByLabel[label]
		if !ok {
			continue
		}
		if ev.Label == "凭据" && ev.Action == "网络发送" {
			return "high"
		}
		if (ev.Label == "会话标识" || ev.Label == "手机号" || ev.Label == "邮箱" || ev.Label == "姓名" || ev.Label == "地址") && ev.Action == "网络发送" {
			hasMediumExternal = true
		}
		if (ev.Label == "会话标识" || ev.Label == "手机号" || ev.Label == "邮箱" || ev.Label == "姓名" || ev.Label == "地址") && (ev.Action == "日志输出" || ev.Action == "持久化") {
			hasMediumStorage = true
		}
	}
	if hasMediumExternal {
		return "medium-external"
	}
	if hasMediumStorage {
		return "medium-storage"
	}
	return ""
}

type signalEvidence struct {
	Label    string
	Location string
	Snippet  string
	Action   string
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
	"订单信息": {"order_id", "order_no", "订单"},
	"会话标识": {"session", "cookie", "access_token", "auth_token", "refresh_token", "bearer", "authorization", "会话"},
	"凭据":   {"api_key", "apikey", "secret", "password", "credential", "密钥", "私钥", "凭据"},
}

func collectSensitiveSignals(text, source string, lineMode bool, requireAction bool) ([]string, []signalEvidence) {
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

			location := source
			snippet := ""
			if lineMode {
				bestEvidence := signalEvidence{}
				for i, line := range lines {
					lowerLine := strings.ToLower(line)
					if !matchesSensitiveKey(lowerLine, k) {
						continue
					}
					action := detectSensitiveCollectionAction(lowerLine)
					if requireAction && action == "" {
						continue
					}
					if shouldSkipSemanticLine(strings.TrimSpace(line)) {
						continue
					}
					candidate := signalEvidence{
						Label:    label,
						Location: fmt.Sprintf("%s:%d", source, i+1),
						Snippet:  formatCodeContext(lines, i, 1),
						Action:   action,
					}
					if bestEvidence.Location == "" || sensitiveActionRank(candidate.Action) > sensitiveActionRank(bestEvidence.Action) {
						bestEvidence = candidate
					}
				}
				if requireAction && bestEvidence.Location == "" {
					continue
				}
				if bestEvidence.Location != "" {
					location = bestEvidence.Location
					snippet = bestEvidence.Snippet
					evidences = append(evidences, bestEvidence)
				}
			} else {
				snippet = strings.TrimSpace(text)
				if len(snippet) > 200 {
					snippet = snippet[:200] + "..."
				}
			}

			labels = append(labels, label)
			matched = true

			if !lineMode {
				evidences = append(evidences, signalEvidence{
					Label:    label,
					Location: location,
					Snippet:  snippet,
				})
			}
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
		key := item.Label + "|" + item.Location + "|" + item.Action
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
		if item.Action != "" {
			out = append(out, fmt.Sprintf("%s@%s(%s)", item.Label, loc, item.Action))
		} else {
			out = append(out, fmt.Sprintf("%s@%s", item.Label, loc))
		}
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
		if ev.Action != "" {
			out = append(out, fmt.Sprintf("%s@%s(%s)", label, defaultEvidenceLocation(ev.Location), ev.Action))
		} else {
			out = append(out, fmt.Sprintf("%s@%s", label, defaultEvidenceLocation(ev.Location)))
		}
	}
	return uniqueStrings(out)
}

func filterSensitiveLabelsByEvidence(labels []string, evidenceByLabel map[string]signalEvidence) []string {
	out := make([]string, 0, len(labels))
	for _, label := range labels {
		ev, ok := evidenceByLabel[label]
		if !ok {
			continue
		}
		if shouldSuppressSensitiveSignal(ev) {
			continue
		}
		out = append(out, label)
	}
	return uniqueStrings(out)
}

func shouldSuppressSensitiveSignal(ev signalEvidence) bool {
	if ev.Label == "订单信息" && ev.Action == "输入接收" {
		return true
	}
	return false
}

func isSQLWriteOperation(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" {
		return false
	}
	sqlWriteKeywords := []string{"insert ", "update ", "delete ", "replace ", "upsert ", "create table", "alter table", "drop table"}
	if cfg := reviewPolicyConfig(); cfg != nil {
		sqlWriteKeywords = cfg.EffectiveSQLWriteKeywords(sqlWriteKeywords)
	}
	if containsAny(lower, sqlWriteKeywords...) {
		return true
	}
	if strings.Contains(lower, "execute(") || strings.Contains(lower, "executemany") {
		return containsAny(lower, sqlWriteKeywords...)
	}
	return false
}

func sensitiveActionRank(action string) int {
	switch action {
	case "网络发送":
		return 4
	case "日志输出":
		return 3
	case "持久化":
		return 2
	case "输入接收":
		return 1
	default:
		return 0
	}
}

func matchesSensitiveKey(line, key string) bool {
	if key == "" {
		return false
	}
	pattern := regexp.MustCompile(`(?i)(^|[^a-z0-9])` + regexp.QuoteMeta(key) + `([^a-z0-9]|$)`)
	return pattern.MatchString(line)
}

func detectSensitiveCollectionAction(line string) string {
	networkSendKeywords := []string{"requests.post", "requests.put", "requests.request", "http.post", "httpx.post", "aiohttp", "fetch(", "axios.post", "axios.put", "send(", "webhook", "upload", "callback"}
	logOutputKeywords := []string{"logger.", "log_", "log.", "print(", "fmt.printf", "fmt.println"}
	persistenceKeywords := []string{"save", "write", "store", "persist", "db.", "redis", ".set("}
	inputReceiveKeywords := []string{"request.", "req.", "header", "headers", "query", "params", "payload", "body", "form", "input", "getenv", "os.getenv"}
	if cfg := reviewPolicyConfig(); cfg != nil {
		keywords := cfg.EffectiveSensitiveActionKeywords()
		if len(keywords.NetworkSend) > 0 {
			networkSendKeywords = keywords.NetworkSend
		}
		if len(keywords.LogOutput) > 0 {
			logOutputKeywords = keywords.LogOutput
		}
		if len(keywords.Persistence) > 0 {
			persistenceKeywords = keywords.Persistence
		}
		if len(keywords.InputReceive) > 0 {
			inputReceiveKeywords = keywords.InputReceive
		}
	}
	switch {
	case containsAny(line, networkSendKeywords...):
		return "网络发送"
	case containsAny(line, logOutputKeywords...):
		return "日志输出"
	case containsAny(line, persistenceKeywords...) || isSQLWriteOperation(line):
		return "持久化"
	case containsAny(line, inputReceiveKeywords...):
		return "输入接收"
	default:
		return ""
	}
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

func (e *Evaluator) evaluateDependencyVulnsFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	if skill == nil {
		return rule.Weight, false, "", nil, fmt.Errorf("skill is nil")
	}
	hasManifest := false
	for _, file := range skill.Files {
		if isDependencyManifestPath(file.Path) {
			hasManifest = true
			break
		}
	}
	if len(skill.Dependencies) == 0 && !hasManifest {
		inferred := inferDependenciesFromSourceFiles(skill.Files)
		if len(inferred) == 0 {
			details := []FindingDetail{{
				RuleID:      rule.ID,
				Severity:    "中风险",
				Title:       rule.Name,
				Description: "未发现依赖清单，且无法从源码推断第三方依赖，依赖漏洞检测置信度不足。",
				Location:    "项目根目录",
				CodeSnippet: "建议补充 go.mod、package.json、requirements.txt 等依赖清单文件。",
			}}
			return rule.Weight * 0.7, false, "", details, nil
		}
		details := []FindingDetail{{
			RuleID:      rule.ID,
			Severity:    "中风险",
			Title:       rule.Name,
			Description: fmt.Sprintf("未发现依赖清单，已从源码推断到 %d 个外部依赖，但缺少版本信息，无法完成漏洞精确比对。", len(inferred)),
			Location:    "源码导入语句",
			CodeSnippet: "建议补充依赖清单并锁定版本。",
		}}
		return rule.Weight * 0.6, false, "", details, nil
	}
	if hasManifest && len(skill.Dependencies) == 0 {
		details := []FindingDetail{{
			RuleID:      rule.ID,
			Severity:    "中风险",
			Title:       rule.Name,
			Description: "检测到依赖清单文件，但未解析到有效依赖，可能存在格式异常或依赖未声明。",
			Location:    "依赖清单",
			CodeSnippet: "请检查 go.mod/package.json/requirements.txt 等文件格式与内容。",
		}}
		return rule.Weight * 0.7, false, "", details, nil
	}
	assessment := e.assessDependencyRisk(context.Background(), skill)
	score := clampScore(rule.Weight-assessment.ScoreDeduction, 0, rule.Weight)
	if len(assessment.Findings) == 0 {
		return score, false, "", nil, nil
	}
	details := make([]FindingDetail, 0, len(assessment.Findings))
	for _, detail := range assessment.Findings {
		detail.RuleID = rule.ID
		detail.Title = rule.Name
		details = append(details, detail)
	}
	return score, false, "", details, nil
}

func (e *Evaluator) evaluateTyposquatRiskFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	if skill == nil {
		return rule.Weight, false, "", nil, fmt.Errorf("skill is nil")
	}
	assessment := e.assessDependencyRisk(context.Background(), skill)
	details := make([]FindingDetail, 0)
	penalty := 0.0
	for _, detail := range assessment.Findings {
		if !strings.Contains(detail.Description, "拼写劫持") && !strings.Contains(detail.Description, "高相似") && !strings.Contains(detail.Description, "恶意") {
			continue
		}
		penalty += 6
		detail.RuleID = rule.ID
		detail.Title = rule.Name
		details = append(details, detail)
	}
	if len(details) == 0 {
		return rule.Weight, false, "", nil, nil
	}
	score := clampScore(rule.Weight-minFloat64(rule.Weight, penalty), 0, rule.Weight)
	return score, false, "", details, nil
}

func inferDependenciesFromSourceFiles(files []SourceFile) []Dependency {
	goImportRe := regexp.MustCompile(`"([a-zA-Z0-9._-]+\.[a-zA-Z0-9._/-]+)"`)
	jsImportRe := regexp.MustCompile(`(?m)(?:from\s+['\"]([^'\"]+)['\"]|require\(\s*['\"]([^'\"]+)['\"]\s*\))`)
	pyImportRe := regexp.MustCompile(`(?m)^(?:from\s+([a-zA-Z0-9_\.]+)\s+import|import\s+([a-zA-Z0-9_\.]+))`)

	seen := make(map[string]struct{})
	out := make([]Dependency, 0)
	for _, f := range files {
		content := f.AnalysisContent()
		switch f.Language {
		case "go":
			for _, m := range goImportRe.FindAllStringSubmatch(content, -1) {
				if len(m) < 2 {
					continue
				}
				name := strings.TrimSpace(m[1])
				if name == "" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "/") {
					continue
				}
				if _, ok := seen[name]; ok {
					continue
				}
				seen[name] = struct{}{}
				out = append(out, Dependency{Name: name, Version: ""})
			}
		case "javascript", "typescript":
			for _, m := range jsImportRe.FindAllStringSubmatch(content, -1) {
				name := strings.TrimSpace(defaultText(m[1], m[2]))
				if name == "" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "/") {
					continue
				}
				if _, ok := seen[name]; ok {
					continue
				}
				seen[name] = struct{}{}
				out = append(out, Dependency{Name: name, Version: ""})
			}
		case "python":
			for _, m := range pyImportRe.FindAllStringSubmatch(content, -1) {
				name := strings.TrimSpace(defaultText(m[1], m[2]))
				if idx := strings.Index(name, "."); idx > 0 {
					name = name[:idx]
				}
				if name == "" || strings.HasPrefix(name, "_") {
					continue
				}
				if _, ok := seen[name]; ok {
					continue
				}
				seen[name] = struct{}{}
				out = append(out, Dependency{Name: name, Version: ""})
			}
		}
	}
	return out
}

func (e *Evaluator) evaluatePermissionsFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	if skill == nil {
		return rule.Weight, false, "", nil, fmt.Errorf("skill is nil")
	}
	if len(skill.Permissions) == 0 {
		return rule.Weight, false, "", nil, fmt.Errorf("permissions detector skipped: no declared permissions")
	}
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
	return score, false, "", details, nil
}

func (e *Evaluator) evaluateContextLeakFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	if skill == nil {
		return rule.Weight, false, "", nil, fmt.Errorf("skill is nil")
	}
	if len(skill.Files) == 0 {
		return rule.Weight, false, "", nil, fmt.Errorf("context leak detector skipped: no source files")
	}
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
		return score, false, "", nil, nil
	}

	if phase3Scoped {
		score = rule.Weight * 0.35
	} else {
		score = rule.Weight * 0.6
	}
	return score, false, "", details, nil
}

func (e *Evaluator) evaluateSoftDependenciesFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	if skill == nil {
		return rule.Weight, false, "", nil, fmt.Errorf("skill is nil")
	}
	if len(skill.Files) == 0 {
		return rule.Weight, false, "", nil, fmt.Errorf("soft dependency detector skipped: no source files")
	}
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
	return score, false, "", details, nil
}

func (e *Evaluator) evaluateCredentialIsolationFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	if skill == nil {
		return rule.Weight, false, "", nil, fmt.Errorf("skill is nil")
	}
	if len(skill.Files) == 0 {
		return rule.Weight, false, "", nil, fmt.Errorf("credential isolation detector skipped: no source files")
	}
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
			if shouldSkipExecutableSignalLine(trimmed) {
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
		return score, false, "", nil, nil
	}
	if phase3Scoped {
		score = rule.Weight * 0.35
	} else {
		score = rule.Weight * 0.6
	}
	return score, false, "", details, nil
}

func (e *Evaluator) evaluateHiddenContentFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	score := e.evaluateHiddenContent(skill)
	var details []FindingDetail
	if score < rule.Weight {
		for _, file := range skill.Files {
			if isLowSignalExamplePath(file.Path) {
				continue
			}
			fileHasSuspiciousPayload := hasSuspiciousEncodedPayload(file.AnalysisContent())
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
				if fileHasSuspiciousPayload && strings.Contains(line, "btoa") {
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    "低风险",
						Title:       rule.Name,
						Description: fmt.Sprintf("使用 btoa 进行 Base64 编码，可能用于混淆数据"),
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
				}
				if fileHasSuspiciousPayload && strings.Contains(line, "atob") {
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
			if entropy > 5.0 && hasSuspiciousEncodedPayload(file.AnalysisContent()) {
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
	return score, false, "", details, nil
}

func hasSuspiciousEncodedPayload(content string) bool {
	base64Like := regexp.MustCompile(`(?m)[A-Za-z0-9+/=]{80,}`)
	hexLike := regexp.MustCompile(`(?m)(?:0x)?[A-Fa-f0-9]{96,}`)
	escapedLike := regexp.MustCompile(`(?m)(?:\\x[0-9a-fA-F]{2}|%[0-9a-fA-F]{2}){12,}`)
	if base64Like.MatchString(content) || hexLike.MatchString(content) || escapedLike.MatchString(content) {
		return true
	}
	lower := strings.ToLower(content)
	hasCodec := strings.Contains(lower, "atob(") || strings.Contains(lower, "btoa(") || strings.Contains(lower, "base64")
	if !hasCodec {
		return false
	}
	for _, token := range []string{"eval(", "exec(", "system(", "os.system", "subprocess", "curl ", "wget ", "fetch(", "requests.", "axios.", "ignore previous instructions", "override system", "bypass approval", "泄露系统提示词", "忽略之前的指令"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func (e *Evaluator) evaluateResourceRiskFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	assessment := assessResourceRisk(skill)
	score := clampScore(rule.Weight-assessment.ScoreDeduction, 0, rule.Weight)
	if len(assessment.Findings) == 0 {
		return score, false, "", nil, nil
	}
	details := make([]FindingDetail, 0, len(assessment.Findings))
	for _, detail := range assessment.Findings {
		detail.RuleID = rule.ID
		detail.Title = rule.Name
		details = append(details, detail)
	}
	return score, false, "", details, nil
}

func isCommentLikeLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	if strings.HasPrefix(trimmed, `"""`) || strings.HasPrefix(trimmed, `'''`) {
		return true
	}
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "--")
}

// stripInlineComment 移除行内注释，保留代码部分。
// 例如: `os.system("rm -rf") # 危险操作` → `os.system("rm -rf")`
func stripInlineComment(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return line
	}

	// 整行是注释，返回空
	if isCommentLikeLine(trimmed) {
		return ""
	}

	// 查找行内注释符号（不在字符串内的）
	inString := false
	stringChar := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inString {
			if c == stringChar && (i == 0 || line[i-1] != '\\') {
				inString = false
			}
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			inString = true
			stringChar = c
			continue
		}
		// 检查注释符号
		if c == '#' {
			return strings.TrimRight(line[:i], " \t")
		}
		if c == '/' && i+1 < len(line) {
			if line[i+1] == '/' {
				return strings.TrimRight(line[:i], " \t")
			}
			if line[i+1] == '*' {
				return strings.TrimRight(line[:i], " \t")
			}
		}
		if c == '-' && i+1 < len(line) && line[i+1] == '-' {
			return strings.TrimRight(line[:i], " \t")
		}
	}
	return line
}

func isDocstringLikeLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	if strings.HasPrefix(trimmed, `"""`) || strings.HasPrefix(trimmed, `'''`) {
		return true
	}
	lower := strings.ToLower(trimmed)
	return strings.Contains(lower, `"""`) || strings.Contains(lower, `'''`) || isLowSignalNarrativeText(lower)
}

var localHostTokens = []string{"localhost", "127.0.0.1", "0.0.0.0", "::1"}
var privateNetworkPrefixes = []string{"10.", "192.168.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."}
var internalNetworkTargets = append([]string{"metadata.google"}, append([]string{}, localHostTokens...)...)
var lowSignalPathParts = []string{"docs", "doc", "examples", "example", "fixtures", "fixture", "testdata", "samples", "sample", "tests", "test", "__tests__", "spec"}
var lowSignalPathSuffixes = []string{"_test.go", ".test.js", ".test.ts", ".spec.js", ".spec.ts", ".md"}

func isPrivateOrLocalHostText(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	for _, token := range localHostTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	for _, prefix := range privateNetworkPrefixes {
		if strings.Contains(lower, prefix) {
			return true
		}
	}
	return false
}

func isLowSignalExamplePath(path string) bool {
	normalized := strings.ToLower(filepath.ToSlash(path))
	parts := strings.Split(normalized, "/")
	for _, part := range parts {
		for _, token := range lowSignalPathParts {
			if part == token {
				return true
			}
		}
	}
	base := filepath.Base(normalized)
	for _, suffix := range lowSignalPathSuffixes {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

func isLowSignalNarrativeText(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	return strings.Contains(lower, "smoke test") || strings.Contains(lower, "imports without error") || strings.Contains(lower, "imports without")
}

func shouldSkipSemanticLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}
	return isCommentLikeLine(trimmed) || isDocstringLikeLine(trimmed)
}

func shouldSkipExecutableSignalLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if shouldSkipSemanticLine(trimmed) {
		return true
	}
	return isLikelyLogOnlyLine(trimmed)
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
	if regexp.MustCompile(`(?i)(os\.environ|getenv\(|os\.getenv\(|process\.env)`).MatchString(line) && regexp.MustCompile(`(?i)(token|secret|password|api[_-]?key|credential|auth)`).MatchString(line) {
		return true
	}
	if regexp.MustCompile(`(?i)(authorization\s*[:=]|bearer\s+)`).MatchString(line) {
		return true
	}
	if regexp.MustCompile(`(?i)(readfile|open\(|read_text\(|read\()`).MatchString(line) && regexp.MustCompile(`(?i)(\.env\b|\.netrc\b|\.npmrc\b|\.pypirc\b|id_rsa|credentials?|secret|token)`).MatchString(line) {
		return true
	}
	if regexp.MustCompile(`(?i)(cat\s+|type\s+|copy\s+|cp\s+)`).MatchString(line) && regexp.MustCompile(`(?i)(/etc/shadow|/root/\.netrc|id_rsa|credentials?\.(json|ya?ml)|\.env\b)`).MatchString(line) {
		return true
	}
	return false
}

func looksLikeNetworkExecution(line string) bool {
	trimmed := strings.TrimSpace(line)
	if shouldSkipSemanticLine(trimmed) {
		return false
	}
	return regexp.MustCompile(`(?i)(requests\.(get|post|put|delete|head|request)\(|fetch\(|axios\.(get|post|put|delete|request)\(|http\.(Get|Post|NewRequest)\(|urllib\.request\.(urlopen|Request|urlretrieve)\(|client\.do\(|net\.dial\(|curl\s+[^#\n]*https?://|wget\s+[^#\n]*https?://)`).MatchString(trimmed)
}

func looksLikeCommandExecution(line string) bool {
	trimmed := strings.TrimSpace(line)
	if shouldSkipSemanticLine(trimmed) {
		return false
	}
	return regexp.MustCompile(`(?i)(subprocess\.(run|popen|call|check_call|check_output)\(|os\.system\(|exec\.Command\(|child_process\.(exec|spawn|execfile|fork)\(|Runtime\.getRuntime\(\)\.exec\(|system\(|popen\(|eval\()`).MatchString(trimmed)
}

func looksLikeDestructiveExecution(line string) bool {
	trimmed := strings.TrimSpace(line)
	if shouldSkipSemanticLine(trimmed) {
		return false
	}
	if regexp.MustCompile(`(?i)(write_data_by_identifier\(|routine_control\(|request_download\(|transfer_data\(|ecu\.(write|flash|erase)|firmware)`).MatchString(trimmed) {
		return true
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

func looksLikeAutoTradingExecution(line string) bool {
	trimmed := strings.TrimSpace(line)
	if shouldSkipSemanticLine(trimmed) {
		return false
	}
	return regexp.MustCompile(`(?i)(create_order\(|signed_order|order_args|submit_order\(|place_order\(|live[_ ]trading|wallet[_-]?private[_-]?key|private_key|clob|polymarket)`).MatchString(trimmed)
}

func looksLikeMaliciousPersistenceOrC2(line string) bool {
	trimmed := strings.TrimSpace(line)
	if shouldSkipSemanticLine(trimmed) {
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

func (e *Evaluator) evaluateMemoryIsolationFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
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
		return score, false, "", nil, nil
	}
	if phase3Scoped {
		score = rule.Weight * 0.35
	} else {
		score = rule.Weight * 0.6
	}
	return score, false, "", details, nil
}

func (e *Evaluator) evaluateSSRFProtectionFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	if skill == nil {
		return rule.Weight, false, "", nil, fmt.Errorf("skill is nil")
	}
	hasSource := false
	for _, file := range skill.Files {
		if isProductionSourceFile(file.Path) {
			hasSource = true
			break
		}
	}
	if !hasSource {
		return rule.Weight, false, "", nil, fmt.Errorf("ssrf detector skipped: no production source files")
	}
	score := rule.Weight
	var details []FindingDetail

	requestKeys := []string{"http.get(", "http.post(", "requests.get(", "requests.post(", "fetch(", "client.do("}
	controlKeys := []string{"allowlist", "whitelist", "denylist", "parseurl", "validate", "isprivateip", "net.parseip", "校验", "白名单"}
	localTargetKeys := []string{"169.254.169.254", "metadata.google", "localhost", "127.0.0.1", "0.0.0.0", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."}

	phase1Hit := false
	phase2Protected := false
	phase3Scoped := false

	for _, file := range skill.Files {
		lines := strings.Split(file.AnalysisContent(), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if shouldSkipSemanticLine(trimmed) {
				continue
			}
			lower := strings.ToLower(trimmed)
			if containsAny(lower, requestKeys...) {
				window := strings.ToLower(joinNearbyLines(lines, i, 3))
				requestCall := strings.TrimSpace(trimmed)
				inputSignal, inputKind := detectSSRFSinkInput(window, requestCall)
				if inputKind == "" {
					continue
				}
				phase1Hit = true
				if containsAny(window, controlKeys...) {
					phase2Protected = true
				}
				controlSignal := firstMatchedToken(window, controlKeys)
				if controlSignal == "" {
					controlSignal = "missing-guard"
				}
				targetSignal := firstMatchedToken(window, localTargetKeys)
				if targetSignal == "" {
					targetSignal = detectInlineRequestTarget(requestCall)
				}
				if targetSignal != "" && (isPrivateOrLocalHostText(targetSignal) || strings.Contains(targetSignal, "metadata.google")) {
					phase3Scoped = true
				}
				targetDesc := targetSignal
				if targetDesc == "" {
					targetDesc = "external target scope"
				}
				if !phase2Protected {
					sev := "中风险"
					desc := fmt.Sprintf("三段判定命中：请求调用=%s；输入来源=%s；来源类型=%s；缺少校验=%s。用户可控输入参与外部请求，且未识别到目标校验/白名单控制。", requestCall, inputSignal, inputKind, controlSignal)
					if phase3Scoped {
						sev = "高风险"
						desc = fmt.Sprintf("三段判定命中：请求调用=%s；输入来源=%s；来源类型=%s；危险目标=%s；缺少校验=%s。用户可控输入参与请求，且存在内网/元数据目标范围，未识别到校验控制。", requestCall, inputSignal, inputKind, targetDesc, controlSignal)
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
		return score, false, "", nil, nil
	}
	if phase3Scoped {
		score = rule.Weight * 0.25
	} else {
		score = rule.Weight * 0.55
	}
	return score, false, "", details, nil
}

func detectSSRFSinkInput(window, requestCall string) (string, string) {
	requestCall = strings.ToLower(strings.TrimSpace(requestCall))
	window = strings.ToLower(strings.TrimSpace(window))
	if requestCall == "" || window == "" {
		return "", ""
	}
	inlineTarget := detectInlineRequestTarget(requestCall)
	if inlineTarget != "" && isPrivateOrLocalHostText(inlineTarget) && !strings.Contains(inlineTarget, "metadata.google") {
		return "", ""
	}
	if strings.Contains(window, "os.getenv") || strings.Contains(window, "getenv(") || strings.Contains(window, "license_server") {
		if strings.Contains(requestCall, "license_server") || strings.Contains(window, "license_server") {
			return "", ""
		}
		if signal := detectConfigurableRequestTarget(window, requestCall); signal != "" {
			return signal, "config_value"
		}
		return "", ""
	}
	if signal := detectControllableRequestTarget(window, requestCall); signal != "" {
		return signal, "user_input"
	}
	if signal := detectConfigurableRequestTarget(window, requestCall); signal != "" {
		return signal, "config_value"
	}
	return "", ""
}

func detectControllableRequestTarget(window, requestCall string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`request\.args\.get\(["']([^"']+)["']`),
		regexp.MustCompile(`request\.form\.get\(["']([^"']+)["']`),
		regexp.MustCompile(`request\.json\.get\(["']([^"']+)["']`),
		regexp.MustCompile(`req\.query\.([a-z0-9_]+)`),
		regexp.MustCompile(`req\.params\.([a-z0-9_]+)`),
		regexp.MustCompile(`req\.body\.([a-z0-9_]+)`),
	}
	for _, re := range patterns {
		if match := re.FindStringSubmatch(window); len(match) > 1 {
			return strings.TrimSpace(match[1])
		}
	}
	if strings.Contains(window, "user input") || strings.Contains(window, "untrusted") {
		if signal := detectRequestArgumentName(requestCall); signal != "" {
			return signal
		}
		return "user_input"
	}
	if signal := detectRequestArgumentName(requestCall); signal != "" && isLikelyURLLikeIdentifier(signal) {
		if strings.Contains(window, "def ") || strings.Contains(window, "func ") || strings.Contains(window, "function ") {
			return signal
		}
	}
	return ""
}

func detectConfigurableRequestTarget(window, requestCall string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`os\.getenv\(["']([^"']+)["']`),
		regexp.MustCompile(`getenv\(["']([^"']+)["']`),
		regexp.MustCompile(`config(?:uration)?(?:\[[^\]]+\]|\.[a-z0-9_]+)`),
	}
	for _, re := range patterns {
		if match := re.FindStringSubmatch(window); len(match) > 1 {
			return strings.TrimSpace(match[1])
		}
		if matched := strings.TrimSpace(re.FindString(window)); matched != "" {
			return matched
		}
	}
	if signal := detectRequestArgumentName(requestCall); signal != "" && strings.Contains(window, signal+" = ") {
		if strings.Contains(window, "config") || strings.Contains(window, "env") {
			return signal
		}
	}
	return ""
}

func detectRequestArgumentName(requestCall string) string {
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`requests\.(?:get|post|put|delete|request)\(([^,)]+)`),
		regexp.MustCompile(`http\.(?:get|post)\(([^,)]+)`),
		regexp.MustCompile(`fetch\(([^,)]+)`),
	} {
		if match := re.FindStringSubmatch(requestCall); len(match) > 1 {
			arg := strings.TrimSpace(strings.Trim(match[1], `"'`))
			if arg != "" && !strings.HasPrefix(arg, "http://") && !strings.HasPrefix(arg, "https://") {
				return arg
			}
		}
	}
	return ""
}

func isLikelyURLLikeIdentifier(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	for _, token := range []string{"url", "uri", "path", "host", "target", "endpoint", "addr", "address"} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}

func detectInlineRequestTarget(requestCall string) string {
	requestCall = strings.ToLower(strings.TrimSpace(requestCall))
	for _, quote := range []string{"\"http://", "\"https://", "'http://", "'https://"} {
		idx := strings.Index(requestCall, quote)
		if idx < 0 {
			continue
		}
		segment := requestCall[idx+1:]
		for _, sep := range []string{"\"", "'", ")", ",", " + "} {
			if cut := strings.Index(segment, sep); cut >= 0 {
				segment = segment[:cut]
				break
			}
		}
		return strings.TrimSpace(segment)
	}
	return ""
}

func firstMatchedToken(text string, needles []string) string {
	for _, needle := range needles {
		if strings.Contains(text, strings.ToLower(strings.TrimSpace(needle))) {
			return strings.TrimSpace(needle)
		}
	}
	return ""
}

func (e *Evaluator) evaluateLicenseValidationConfigFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	details := make([]FindingDetail, 0)
	for _, file := range skill.Files {
		if isLowSignalExamplePath(file.Path) {
			continue
		}
		details = append(details, detectFailOpenLicenseRisk(file, rule)...)
	}
	if len(details) == 0 {
		return rule.Weight, false, "", nil, nil
	}
	if rule.OnFail.Action == "block" {
		return 0, true, rule.OnFail.Reason, details, nil
	}
	return rule.Weight * 0.4, false, "", details, nil
}

func detectFailOpenLicenseRisk(file SourceFile, rule config.Rule) []FindingDetail {
	lines := strings.Split(file.Content, "\n")
	funcDeclRe := regexp.MustCompile(`(?i)^\s*(def|func|function)\s+([a-zA-Z_][a-zA-Z0-9_]*)`)
	licenseFuncNameRe := regexp.MustCompile(`(?i)(validate|check|auth|license|licence|entitle|pro)`)
	remoteCallRe := regexp.MustCompile(`(?i)(requests\.(get|post|request)|http\.(get|post)|client\.do\(|fetch\()`)
	emptyExceptRe := regexp.MustCompile(`(?ms)except[^\n]*:\s*(\n\s*(pass|continue)\s*)+`)
	only200Re := regexp.MustCompile(`(?i)(status[_\s]*code\s*==\s*200|==\s*http\.statusok)`)
	validCheckRe := regexp.MustCompile(`(?i)(data\.get\(["']valid["']\)|["']valid["']\s*:\s*true|\bvalid\b\s*==\s*true|\bvalid\b\s*is\s*true)`)
	defaultDenyRe := regexp.MustCompile(`(?i)(return\s+false|return\s+0|return\s+nil\s*,\s*false)`)

	type fnRange struct {
		name      string
		startLine int
		endLine   int
	}
	ranges := make([]fnRange, 0)
	for i, line := range lines {
		m := funcDeclRe.FindStringSubmatch(line)
		if len(m) < 3 {
			continue
		}
		ranges = append(ranges, fnRange{name: strings.ToLower(m[2]), startLine: i, endLine: len(lines) - 1})
	}
	for i := 0; i < len(ranges)-1; i++ {
		ranges[i].endLine = ranges[i+1].startLine - 1
	}

	details := make([]FindingDetail, 0)
	for _, fn := range ranges {
		if !licenseFuncNameRe.MatchString(fn.name) {
			continue
		}
		if fn.startLine < 0 || fn.startLine >= len(lines) || fn.endLine < fn.startLine {
			continue
		}
		block := strings.Join(lines[fn.startLine:fn.endLine+1], "\n")
		if !remoteCallRe.MatchString(block) {
			continue
		}
		hasEmptyExcept := emptyExceptRe.MatchString(block)
		onlyCheck200 := only200Re.MatchString(block)
		noValidCheck := !validCheckRe.MatchString(block)
		noDefaultDeny := !defaultDenyRe.MatchString(block)
		if hasEmptyExcept && onlyCheck200 && noValidCheck && noDefaultDeny {
			details = append(details, FindingDetail{
				RuleID:      rule.ID,
				Severity:    "高风险",
				Title:       rule.Name,
				Description: "许可证校验存在 Fail-Open：异常分支未拒绝、仅判断状态码、未校验 valid 字段且无默认拒绝返回。",
				Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), fn.startLine+1),
				CodeSnippet: formatCodeContext(lines, fn.startLine, 6),
			})
		}
	}
	return details
}

func (e *Evaluator) evaluatePathTraversalFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	patterns := []patternRisk{
		{regexp.MustCompile(`(?i)(open|readfile|writefile|read_file|write_file|os\.open|ioutil\.ReadFile|os\.ReadFile).*\.\./`), "文件 API 使用路径遍历片段"},
		{regexp.MustCompile(`(?i)(filepath\.Join|path\.join|os\.path\.join).*?(input|param|query|user|request)`), "用户输入参与文件路径拼接"},
		{regexp.MustCompile(`(?i)(/etc/passwd|/root/|~/.ssh|\.ssh/)`), "访问敏感系统路径"},
	}
	score, blocked, reason, details := e.evaluatePatternRiskFunc(skill, rule, "高风险", patterns)
	return score, blocked, reason, details, nil
}

func (e *Evaluator) evaluateInputSchemaFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	patterns := []patternRisk{
		{regexp.MustCompile(`(?i)(json\.loads|JSON\.parse|yaml\.safe_load|req\.body|request\.json|input\()`), "输入解析附近未识别到 Schema 或校验控制"},
		{regexp.MustCompile(`(?i)(args|kwargs|params|query).*?(exec|eval|system|shell)`), "动态参数进入高危执行路径，缺少输入 Schema 约束"},
		{regexp.MustCompile(`(?i)(jsonschema|ajv|zod|pydantic|validate\s*\(\s*schema)`), "发现输入 Schema 相关实现，需要确认是否覆盖外部输入边界"},
	}
	score, blocked, reason, details := e.evaluatePatternRiskFunc(skill, rule, "中风险", patterns)
	return score, blocked, reason, details, nil
}

func (e *Evaluator) evaluateAuditLoggingFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	if skill == nil {
		return rule.Weight, false, "", nil, fmt.Errorf("skill is nil")
	}
	patterns := config.ReviewAuditPatterns{
		SensitiveLog:   `(?i)(log|logger|print|fmt\.print).*(password|token|secret|api[_-]?key|authorization|cookie)`,
		SilentException: `(?i)(except|catch).*?(pass|return\s+nil|return\s+none)`,
		HighImpact:     `(?i)(requests\.(post|put|delete)\(|http\.(post|put|delete)\(|subprocess\.|os\.system\(|exec\.command\(|open\([^\n]*['\"]w|sqlite3\.connect\(|\.execute\(|\.executemany\(|write\(|save\(|persist)`,
		Audit:          `(?i)(audit[_-]?log|security[_-]?log|logger\.(info|warn|error|audit)|logrus|zap\.|logging\.(info|warning|error))`,
	}
	if cfg := reviewPolicyConfig(); cfg != nil {
		patterns = cfg.EffectiveAuditPatterns(patterns)
	}
	sensitiveLogRe := regexp.MustCompile(patterns.SensitiveLog)
	silentExceptionRe := regexp.MustCompile(patterns.SilentException)
	highImpactRe := regexp.MustCompile(patterns.HighImpact)
	auditRe := regexp.MustCompile(patterns.Audit)

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
			lower := strings.ToLower(trimmed)
			switch {
			case sensitiveLogRe.MatchString(lower):
				details = append(details, FindingDetail{
					RuleID:      rule.ID,
					Severity:    "中风险",
					Title:       rule.Name,
					Description: "日志或输出包含敏感字段且未识别到脱敏",
					Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
					CodeSnippet: formatCodeContext(lines, i, 2),
				})
			case silentExceptionRe.MatchString(lower):
				window := strings.ToLower(joinNearbyLines(lines, i, 2))
				if auditRe.MatchString(window) {
					continue
				}
				details = append(details, FindingDetail{
					RuleID:      rule.ID,
					Severity:    "中风险",
					Title:       rule.Name,
					Description: "异常路径缺少审计记录",
					Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
					CodeSnippet: formatCodeContext(lines, i, 2),
				})
			case highImpactRe.MatchString(lower):
				window := strings.ToLower(joinNearbyLines(lines, i, 3))
				if auditRe.MatchString(window) {
					continue
				}
				details = append(details, FindingDetail{
					RuleID:      rule.ID,
					Severity:    "低风险",
					Title:       rule.Name,
					Description: "检测到高影响操作附近缺少审计日志或结果记录，后续追溯能力不足",
					Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
					CodeSnippet: formatCodeContext(lines, i, 2),
				})
			}
		}
	}
	if len(details) == 0 {
		return rule.Weight, false, "", nil, nil
	}
	if rule.OnFail.Action == "block" {
		return 0, true, rule.OnFail.Reason, details, nil
	}
	return rule.Weight * 0.4, false, "", details, nil
}

func (e *Evaluator) evaluateSBOMVersionLockFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
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
		return rule.Weight, false, "", nil, nil
	}
	if rule.OnFail.Action == "block" {
		return 0, true, rule.OnFail.Reason, details, nil
	}
	return rule.Weight * 0.4, false, "", details, nil
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

func (e *Evaluator) evaluateTLSProtectionFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	patterns := []patternRisk{
		{regexp.MustCompile(`(?i)InsecureSkipVerify\s*:\s*true|verify\s*=\s*false|rejectUnauthorized\s*:\s*false`), "TLS 证书校验被关闭"},
		{regexp.MustCompile(`(?i)http://[^\s"']+`), "外联地址使用明文 HTTP"},
		{regexp.MustCompile(`(?i)ssl\._create_unverified_context|CERT_NONE`), "使用不校验证书的 TLS 上下文"},
	}
	score, blocked, reason, details := e.evaluatePatternRiskFunc(skill, rule, "中风险", patterns)
	corsDetails := detectCORSWildcardCredentialRisk(skill, rule)
	if len(corsDetails) == 0 {
		return score, blocked, reason, details, nil
	}
	details = append(details, corsDetails...)
	if rule.OnFail.Action == "block" {
		return 0, true, rule.OnFail.Reason, details, nil
	}
	return rule.Weight * 0.4, false, "", details, nil
}

func (e *Evaluator) evaluateFileUploadParsingFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	patterns := []patternRisk{
		{regexp.MustCompile(`(?i)(upload|multipart|multipart/form-data|formfile|UploadFile|SaveUploadedFile|request\.files|multer)`), "存在文件上传入口，需要验证类型、大小和存储位置控制"},
		{regexp.MustCompile(`(?i)(zipfile|tarfile|archive|extractall|untar|unzip).*?(input|upload|file)`), "上传文件或归档解析存在路径穿越/炸弹风险"},
		{regexp.MustCompile(`(?i)(parse|load).*?(pdf|docx|xlsx|image|xml)`), "复杂文件解析需要沙箱、大小限制和异常处理"},
	}
	score, blocked, reason, details := e.evaluatePatternRiskFunc(skill, rule, "中风险", patterns)
	return score, blocked, reason, details, nil
}

func (e *Evaluator) evaluateUnsafeDeserializationFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	patterns := []patternRisk{
		{regexp.MustCompile(`(?i)pickle\.loads?|pickle\.load|joblib\.load|torch\.load|yaml\.load\(|marshal\.loads?|unsafe[_-]?deserialize`), "使用不安全反序列化或模型文件加载 API"},
		{regexp.MustCompile(`(?i)(ObjectInputStream|BinaryFormatter|readObject\(|deserialize\()`), "使用高风险反序列化 API"},
	}
	score, blocked, reason, details := e.evaluatePatternRiskFunc(skill, rule, "低风险", patterns)
	return score, blocked, reason, details, nil
}

func (e *Evaluator) evaluateDebugBackdoorFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	patterns := []patternRisk{
		{regexp.MustCompile(`(?i)(debug\s*=\s*true|app\.run\(.*debug\s*=\s*true|DEBUG=True)`), "调试模式在代码中开启"},
		{regexp.MustCompile(`(?i)(/debug|/admin/test|test_backdoor|debug_backdoor|admin_backdoor|dev_only|mock_auth|skip_auth)`), "调试接口或测试后门疑似残留"},
	}
	score, blocked, reason, details := e.evaluatePatternRiskFunc(skill, rule, "低风险", patterns)
	return score, blocked, reason, details, nil
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

func (e *Evaluator) evaluateToolResponsePoisoningFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	if skill == nil {
		return rule.Weight, false, "", nil, fmt.Errorf("skill is nil")
	}
	hasSource := false
	for _, file := range skill.Files {
		if isProductionSourceFile(file.Path) {
			hasSource = true
			break
		}
	}
	if !hasSource {
		return rule.Weight, false, "", nil, fmt.Errorf("tool response poisoning detector skipped: no production source files")
	}
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
		return score, false, "", nil, nil
	}
	if phase3Scoped {
		score = rule.Weight * 0.3
	} else {
		score = rule.Weight * 0.6
	}
	return score, false, "", details, nil
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

func (e *Evaluator) evaluateInjectionRiskFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	if skill == nil {
		return rule.Weight, false, "", nil, fmt.Errorf("skill is nil")
	}
	hasSource := false
	for _, file := range skill.Files {
		if isProductionSourceFile(file.Path) {
			hasSource = true
			break
		}
	}
	if !hasSource {
		return rule.Weight, false, "", nil, fmt.Errorf("injection detector skipped: no production source files")
	}
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
	return score, false, "", details, nil
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
				if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || isDocstringLikeLine(trimmed) {
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
