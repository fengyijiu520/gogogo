package docx

import (
	"os"
	"strings"
	"testing"

	"skill-scanner/internal/review"
)

func TestBuildDocumentContainsSequenceSections(t *testing.T) {
	g := NewGenerator()
	result := &review.Result{
		Behavior: review.BehaviorProfile{
			BehaviorTimelines: []string{"sample.go | 时序: 下载(L10,x1) -> 执行(L20,x1)"},
			SequenceAlerts:    []string{"命中下载后执行时序"},
		},
		StructuredFindings: []review.StructuredFinding{
			{
				ID:                  "SF-001",
				RuleID:              "V7-009",
				Title:               "自更新与远程下载执行",
				Severity:            "高风险",
				Category:            "命令执行",
				Confidence:          "高",
				AttackPath:          "下载后执行",
				Evidence:            []string{"scripts/run.py:10"},
				CalibrationBasis:    []string{"存在高危时序告警"},
				FalsePositiveChecks: []string{"确认相关脚本不会进入发布包或动态加载链路"},
				ReviewGuidance:      "优先复核攻击路径",
			},
			{ID: "SF-002", RuleID: "V7-003", Title: "示例外联", Severity: "高风险", Category: "外联与情报", Confidence: "待复核", AttackPath: "example request", Evidence: []string{"examples/demo.py:1"}, ReviewGuidance: "确认是否发布"},
		},
		VulnerabilityBlocks: []review.VulnerabilityBlock{{ID: "SF-001", Format: "structured-vuln-block", Content: "<vuln>\n  <title>自更新与远程下载执行</title>\n</vuln>"}},
		RuleExplanations: []review.RuleExplanation{{
			RuleID:                   "V7-009",
			Name:                     "自更新与远程下载执行",
			Severity:                 "高风险",
			DetectionType:            "pattern",
			Action:                   "block",
			Triggered:                true,
			DetectionCriteria:        []string{"正则模式数量: 3"},
			ExclusionConditions:      []string{"仅在确认相关内容不会进入发布包或动态加载链路时，才可排除。"},
			VerificationRequirements: []string{"确认入口可达性"},
			OutputRequirements:       []string{"输出具体文件路径"},
			PromptTemplateSummary:    "必须先检查排除条件",
			RemediationFocus:         "移除 shell 拼接",
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
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{
			{FindingID: "SF-001", Verdict: "needs_manual_review", Confidence: "中", Reason: "确定性 reviewer 待复核", Fix: "补齐入口证据", Reviewer: "deterministic-vuln-reviewer"},
			{FindingID: "SF-001", Verdict: "confirmed", Confidence: "高", Reason: "LLM 证据闭环", Fix: "优先复核攻击路径", Reviewer: "llm-vuln-reviewer"},
			{FindingID: "SF-002", Verdict: "likely_false_positive", Confidence: "中高", Reason: "已确认示例文件不会进入发布包", Fix: "确认是否发布", Reviewer: "llm-vuln-reviewer"},
		},
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
		}},
		AuditEvents: []review.AuditEvent{{Type: "statusUpdate", StepID: "pipeline-01", Status: "completed", Brief: "沙箱执行完成", ToolName: "sandbox", Timestamp: "2026-04-29T00:00:00Z"}},
	}

	xml := g.buildDocument(nil, 88, "bge-test", false, result, IntentSummary{}, AnalysisProfile{AnalysisMode: "全链路分析"})

	if !strings.Contains(xml, "行为时序链路") {
		t.Fatalf("expected docx xml contains timeline section")
	}
	if !strings.Contains(xml, "时序告警") {
		t.Fatalf("expected docx xml contains sequence alert section")
	}
	if !strings.Contains(xml, "命中下载后执行时序") {
		t.Fatalf("expected docx xml contains sequence alert item")
	}
	if !strings.Contains(xml, "结构化风险发现") || !strings.Contains(xml, "误报检查") || !strings.Contains(xml, "校准依据") || !strings.Contains(xml, "置信度") {
		t.Fatalf("expected docx xml contains structured findings section")
	}
	if !strings.Contains(xml, "能力一致性矩阵") || !strings.Contains(xml, "已声明但沙箱未验证") {
		t.Fatalf("expected docx xml contains capability matrix")
	}
	if !strings.Contains(xml, "结构化审计事件流") || !strings.Contains(xml, "沙箱执行完成") {
		t.Fatalf("expected docx xml contains audit event stream")
	}
	if !strings.Contains(xml, "可复核漏洞块") || !strings.Contains(xml, "structured-vuln-block") || !strings.Contains(xml, "&lt;vuln&gt;") {
		t.Fatalf("expected docx xml contains vulnerability blocks")
	}
	if !strings.Contains(xml, "规则解释卡") || !strings.Contains(xml, "排除条件") || !strings.Contains(xml, "Prompt 摘要") {
		t.Fatalf("expected docx xml contains rule explanations")
	}
	if !strings.Contains(xml, "零误报复核清单") || !strings.Contains(xml, "可利用性") || !strings.Contains(xml, "倾向真实风险") {
		t.Fatalf("expected docx xml contains false-positive review checklist")
	}
	if !strings.Contains(xml, "检测链路对比与优化项") || !strings.Contains(xml, "参考基线领先") || !strings.Contains(xml, "增加二次 LLM 复核阶段") {
		t.Fatalf("expected docx xml contains detection chain comparison")
	}
	if strings.Contains(xml, "AI-Infra-Guard") || strings.Contains(xml, "Based on Tencent") {
		t.Fatalf("expected docx xml to avoid external attribution wording")
	}
	if !strings.Contains(xml, "二次复核 Agent 任务包") || !strings.Contains(xml, "vuln-reviewer") || !strings.Contains(xml, "严格的漏洞复核 Agent") {
		t.Fatalf("expected docx xml contains review agent task package")
	}
	if !strings.Contains(xml, "重点判定条件") || strings.Contains(xml, "阻断条件") {
		t.Fatalf("expected docx xml uses review criteria wording")
	}
	if !strings.Contains(xml, "二次复核 Agent 裁决") || !strings.Contains(xml, "confirmed") || !strings.Contains(xml, "deterministic-vuln-reviewer") {
		t.Fatalf("expected docx xml contains review agent verdicts")
	}
	if !strings.Contains(xml, "最终裁决优先级") || !strings.Contains(xml, "最终采用: 是") || !strings.Contains(xml, "最终复核: 需人工复核 / deterministic-vuln-reviewer+llm-vuln-reviewer") || !strings.Contains(xml, "最终复核: 疑似误报 / llm-vuln-reviewer") {
		t.Fatalf("expected docx xml contains synthesized final verdicts")
	}
	if strings.Index(xml, "SF-001 [高风险]") > strings.Index(xml, "SF-002 [高风险]") {
		t.Fatalf("expected confirmed structured finding before likely false positive")
	}
}

func TestTextFromHTMLReportPreservesPrimarySections(t *testing.T) {
	htmlReport := `<html><body><h1>技能安全审查报告</h1><h2>风险与能力综合研判</h2><p>示例正文</p><pre class="code-box">line1()
line2()</pre><ul><li>修复建议 A</li></ul></body></html>`
	text := TextFromHTMLReport(htmlReport)
	for _, want := range []string{"# 技能安全审查报告", "## 风险与能力综合研判", "示例正文", "```text", "line1()", "- 修复建议 A"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected converted text contains %q, got %q", want, text)
		}
	}
}

func TestDocxFontHelpersPreferConfiguredCJKFont(t *testing.T) {
	original := os.Getenv("REVIEW_REPORT_CJK_FONT")
	t.Cleanup(func() {
		if original == "" {
			_ = os.Unsetenv("REVIEW_REPORT_CJK_FONT")
			return
		}
		_ = os.Setenv("REVIEW_REPORT_CJK_FONT", original)
	})
	if err := os.Setenv("REVIEW_REPORT_CJK_FONT", "Test CJK Font"); err != nil {
		t.Fatalf("set env: %v", err)
	}
	if got := docxCJKFont(); got != "Test CJK Font" {
		t.Fatalf("expected configured cjk font, got %q", got)
	}
	fontTable := docxFontTableXML()
	for _, want := range []string{"Test CJK Font", "Microsoft YaHei", "PingFang SC", "WenQuanYi Micro Hei"} {
		if !strings.Contains(fontTable, want) {
			t.Fatalf("expected font table contains %q, got %q", want, fontTable)
		}
	}
	styles := docxStylesXML()
	if !strings.Contains(styles, `w:eastAsia="Test CJK Font"`) {
		t.Fatalf("expected styles use configured cjk font, got %q", styles)
	}
}
