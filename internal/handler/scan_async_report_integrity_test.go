package handler

import (
	"strings"
	"testing"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

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

func TestPreferredVerdictsByFindingNormalizesLLMAliasesAndDefaults(t *testing.T) {
	preferred := preferredVerdictsByFinding([]review.ReviewAgentVerdict{{
		FindingID: "SF-ALIAS-001",
		Verdict:   "真实风险",
	}})
	got := preferred["SF-ALIAS-001"]
	if got.Verdict != "confirmed" {
		t.Fatalf("expected chinese verdict alias normalized, got %+v", got)
	}
	if got.Confidence == "" || got.Reviewer == "" || got.Reason == "" {
		t.Fatalf("expected missing verdict fields filled, got %+v", got)
	}
}

func TestNormalizeReviewAgentVerdictFallsBackForInvalidVerdict(t *testing.T) {
	got := normalizeReviewAgentVerdict(review.ReviewAgentVerdict{Verdict: "maybe"}, "SF-INVALID-001", "llm-vuln-reviewer", []string{"入口可达性"})
	if got.FindingID != "SF-INVALID-001" || got.Verdict != "needs_manual_review" {
		t.Fatalf("expected invalid verdict fallback, got %+v", got)
	}
	if !containsString(got.MissingEvidence, "复核输出缺少有效 verdict，已归一化为需人工复核") {
		t.Fatalf("expected missing evidence explaining fallback, got %+v", got.MissingEvidence)
	}
	if got.Confidence != "低" || got.Reviewer != "llm-vuln-reviewer" || len(got.StandardsApplied) == 0 {
		t.Fatalf("expected defaults filled, got %+v", got)
	}
}

func TestPreferredVerdictsByFindingPreservesDeterministicDirectConfirmationOnConflict(t *testing.T) {
	preferred := preferredVerdictsByFinding([]review.ReviewAgentVerdict{
		{FindingID: "SF-SSRF", Verdict: "needs_manual_review", Confidence: "中", Reviewer: "llm-vuln-reviewer", Reason: "上下文还需补充"},
		{FindingID: "SF-SSRF", Verdict: "confirmed", Confidence: "高", Reviewer: "deterministic-vuln-reviewer", Reason: "证据已满足直接确认条件，可自动确认为真实风险。"},
	})
	got := preferred["SF-SSRF"]
	if got.Verdict != "confirmed" {
		t.Fatalf("expected deterministic direct confirmation preserved, got %+v", got)
	}
	if got.Reviewer != "deterministic-vuln-reviewer" {
		t.Fatalf("expected deterministic reviewer retained, got %+v", got)
	}
}

func TestPreferredVerdictsByFindingPrefersReasonedFalsePositiveForDocumentationOnlyConflict(t *testing.T) {
	preferred := preferredVerdictsByFinding([]review.ReviewAgentVerdict{
		{FindingID: "SF-021", Verdict: "needs_manual_review", Confidence: "低", Reviewer: "deterministic-vuln-reviewer", Reason: "当前缺少真实发布链路与运行支撑", MissingEvidence: []string{"缺少真实发布链路", "缺少运行链路或行为支撑"}, StandardsApplied: []string{"入口可达性"}},
		{FindingID: "SF-021", Verdict: "likely_false_positive", Confidence: "中高", Reviewer: "llm-vuln-reviewer", Reason: "README 纯文档示例，当前无可达攻击面，不构成可利用漏洞。", MissingEvidence: []string{"缺少真实发布链路"}, StandardsApplied: []string{"证据完整性"}},
	})
	got := preferred["SF-021"]
	if got.Verdict != "likely_false_positive" {
		t.Fatalf("expected reasoned false positive preserved, got %+v", got)
	}
	if got.Confidence != "中高" {
		t.Fatalf("expected medium-high confidence, got %+v", got)
	}
	if !strings.Contains(got.Reviewer, "deterministic-vuln-reviewer") || !strings.Contains(got.Reviewer, "llm-vuln-reviewer") {
		t.Fatalf("expected merged reviewers, got %+v", got)
	}
	if len(got.StandardsApplied) != 2 {
		t.Fatalf("expected merged standards, got %+v", got)
	}
	if !containsString(got.MissingEvidence, "缺少运行链路或行为支撑") {
		t.Fatalf("expected merged missing evidence retained, got %+v", got)
	}
	if !strings.Contains(got.Reason, "无可达攻击面") {
		t.Fatalf("expected fp rationale kept, got %+v", got)
	}
}

func TestPreferredVerdictsByFindingKeepsManualReviewWithoutStrongFalsePositiveRationale(t *testing.T) {
	preferred := preferredVerdictsByFinding([]review.ReviewAgentVerdict{
		{FindingID: "SF-014", Verdict: "needs_manual_review", Confidence: "低", Reviewer: "deterministic-vuln-reviewer", Reason: "需要进一步确认环境影响", MissingEvidence: []string{"缺少运行链路或行为支撑"}},
		{FindingID: "SF-014", Verdict: "likely_false_positive", Confidence: "中", Reviewer: "llm-vuln-reviewer", Reason: "当前证据偏弱。"},
	})
	got := preferred["SF-014"]
	if got.Verdict != "needs_manual_review" {
		t.Fatalf("expected weak false-positive rationale to stay manual review, got %+v", got)
	}
}

func TestPreferredVerdictsByFindingPrefersReasonedFalsePositiveForTemplateOnlyExposureConflict(t *testing.T) {
	preferred := preferredVerdictsByFinding([]review.ReviewAgentVerdict{
		{FindingID: "SF-014", Verdict: "needs_manual_review", Confidence: "低", Reviewer: "deterministic-vuln-reviewer", Reason: "仍需确认是否存在真实暴露面", MissingEvidence: []string{"缺少运行链路或行为支撑"}},
		{FindingID: "SF-014", Verdict: "likely_false_positive", Confidence: "中高", Reviewer: "llm-vuln-reviewer", Reason: "index.html 只是纯 HTML 模板，没有代码实现、没有网络暴露，也不符合暴露面与未鉴权服务漏洞定义。"},
	})
	got := preferred["SF-014"]
	if got.Verdict != "likely_false_positive" {
		t.Fatalf("expected template-only exposure conflict to prefer false positive, got %+v", got)
	}
	if !strings.Contains(got.Reason, "没有代码实现") {
		t.Fatalf("expected template-only rationale kept, got %+v", got)
	}
}

func TestPreferredVerdictsByFindingPrefersReasonedFalsePositiveForEvidenceMismatchConflict(t *testing.T) {
	preferred := preferredVerdictsByFinding([]review.ReviewAgentVerdict{
		{FindingID: "SF-019", Verdict: "needs_manual_review", Confidence: "低", Reviewer: "deterministic-vuln-reviewer", Reason: "需要进一步确认数据最小化影响", MissingEvidence: []string{"缺少运行链路或行为支撑"}},
		{FindingID: "SF-019", Verdict: "likely_false_positive", Confidence: "中高", Reviewer: "llm-vuln-reviewer", Reason: "未发现递归调用，get_config 只是普通文件读取，规则主题与证据不匹配。"},
	})
	got := preferred["SF-019"]
	if got.Verdict != "likely_false_positive" {
		t.Fatalf("expected evidence-mismatch conflict to prefer false positive, got %+v", got)
	}
	if !strings.Contains(got.Reason, "主题与证据不匹配") {
		t.Fatalf("expected mismatch rationale kept, got %+v", got)
	}
}

func TestPreferredVerdictsByFindingPrefersReasonedFalsePositiveForComplianceOnlyConflict(t *testing.T) {
	preferred := preferredVerdictsByFinding([]review.ReviewAgentVerdict{
		{FindingID: "SF-013", Verdict: "needs_manual_review", Confidence: "中", Reviewer: "deterministic-vuln-reviewer", Reason: "仍需确认是否形成真实漏洞", MissingEvidence: []string{"缺少运行链路或行为支撑"}},
		{FindingID: "SF-013", Verdict: "likely_false_positive", Confidence: "中高", Reviewer: "llm-vuln-reviewer", Reason: "功能缺失属于完整性或合规问题，不构成可利用的安全漏洞，且分类与证据不符。"},
	})
	got := preferred["SF-013"]
	if got.Verdict != "likely_false_positive" {
		t.Fatalf("expected compliance-only conflict to prefer false positive, got %+v", got)
	}
	if !strings.Contains(got.Reason, "不构成可利用的安全漏洞") {
		t.Fatalf("expected compliance rationale kept, got %+v", got)
	}
}

func TestEnforceReportConsistencyDowngradesConfirmedWithClosureGaps(t *testing.T) {
	base, refined, integrity := enforceReportConsistency(nil, baseScanOutput{}, review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:               "SF-GAP",
			RuleID:           "V7-009",
			Title:            "命令执行",
			Severity:         "高风险",
			SecurityVerdict:  "confirmed",
			CodeEvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"},
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-GAP", Verdict: "confirmed", Confidence: "高"}},
	})
	_ = base
	if integrity.Status != "passed_with_fixes" {
		t.Fatalf("expected passed_with_fixes integrity, got %+v", integrity)
	}
	if refined.StructuredFindings[0].SecurityVerdict != "review" {
		t.Fatalf("expected confirmed finding downgraded to review, got %+v", refined.StructuredFindings[0])
	}
	if refined.ReviewAgentVerdicts[0].Verdict != "needs_manual_review" || !containsString(refined.ReviewAgentVerdicts[0].MissingEvidence, "报告一致性预检: confirmed 缺少完整证据链闭环") {
		t.Fatalf("expected verdict downgraded with closure gap reason, got %+v", refined.ReviewAgentVerdicts[0])
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

func TestSortFindingsByReviewUsesNormalizedSeverityWhenVerdictRanksMatch(t *testing.T) {
	findings := []plugins.Finding{
		{RuleID: "V7-004", Severity: "高风险", Title: "弱证据凭据访问"},
		{RuleID: "V7-009", Severity: "中风险", Title: "稳定命令执行"},
	}
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:       "SF-LOW",
			RuleID:   "V7-004",
			Severity: "高风险",
			Title:    "弱证据凭据访问",
			Category: "凭据访问",
			Evidence: []string{"docs/guide.md:8 open('/root/.netrc')"},
		}, {
			ID:               "SF-MEDIUM",
			RuleID:           "V7-009",
			Severity:         "中风险",
			Title:            "稳定命令执行",
			Category:         "命令执行",
			Confidence:       "高",
			Evidence:         []string{"scripts/run.py:10 subprocess.run(cmd)", "scripts/run.py:12 os.WriteFile(payload)"},
			CalibrationBasis: []string{"存在高危时序告警"},
		}},
		Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中下载后执行时序"}},
		FalsePositiveReviews: []review.FalsePositiveReview{{
			FindingID:        "SF-LOW",
			Verdict:          "待人工复核: 证据可疑但仍需确认可达性、影响和排除条件。",
			EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。",
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-LOW", Verdict: "needs_manual_review", Reviewer: "llm-vuln-reviewer"}, {FindingID: "SF-MEDIUM", Verdict: "needs_manual_review", Reviewer: "llm-vuln-reviewer"}},
	}
	ordered := sortFindingsByReview(findings, refined)
	if ordered[0].RuleID != "V7-009" || ordered[1].RuleID != "V7-004" {
		t.Fatalf("expected normalized medium risk to sort before downgraded low risk, got %+v", ordered)
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

func TestEnforceReportConsistencyDowngradesConfirmedWithoutTypedEvidence(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:              "SF-001",
			RuleID:          "V7-015",
			Title:           "说明文档中的远程执行描述",
			Severity:        "中风险",
			Category:        "声明与行为差异",
			SecurityVerdict: "confirmed",
			Evidence:        []string{"README.md:12 remote execution example"},
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "confirmed", Confidence: "高", Reviewer: "deterministic-vuln-reviewer"}},
	}
	_, adjusted, integrity := enforceReportConsistency(nil, baseScanOutput{}, refined)
	if adjusted.StructuredFindings[0].SecurityVerdict != "review" {
		t.Fatalf("expected confirmed structured finding downgraded, got %+v", adjusted.StructuredFindings[0])
	}
	if adjusted.ReviewAgentVerdicts[0].Verdict != "needs_manual_review" {
		t.Fatalf("expected confirmed verdict downgraded, got %+v", adjusted.ReviewAgentVerdicts[0])
	}
	if !containsString(integrity.AutoFixes, "已将缺少代码/行为证据的 confirmed 风险降级为需人工复核") {
		t.Fatalf("expected integrity autofix recorded, got %+v", integrity)
	}
}

func TestEnforceReportConsistencyAppendsIntegrityStatusToCoverageNote(t *testing.T) {
	base := baseScanOutput{coverageNote: "已完成当前规则集全量检测"}
	adjustedBase, _, integrity := enforceReportConsistency([]plugins.Finding{{
		PluginName:  "SecurityEngine",
		RuleID:      "S2-P1-012",
		Severity:    "中风险",
		Title:       "SSRF-内网探测",
		Description: "目标 URL 来自用户输入",
		Location:    "client.py:88",
		CodeSnippet: `requests.get(target_url)`,
	}}, base, review.Result{})
	if !strings.Contains(adjustedBase.coverageNote, "报告一致性预检:") {
		t.Fatalf("expected coverage note contains integrity summary, got %q", adjustedBase.coverageNote)
	}
	if !strings.Contains(adjustedBase.coverageNote, "状态="+integrity.Status) {
		t.Fatalf("expected coverage note uses final integrity status %q, got %q", integrity.Status, adjustedBase.coverageNote)
	}
	if len(integrity.MappingGaps) == 0 || !strings.Contains(integrity.MappingGaps[0], "client.py:88") {
		t.Fatalf("expected mapping gap sample for unmapped risk, got %+v", integrity)
	}
}

func TestEnforceReportConsistencyIgnoresExpectedFilteredFindingsWhenCountingMissingMappings(t *testing.T) {
	findings := []plugins.Finding{{
		PluginName:  "BehaviorGuard",
		RuleID:      "V7-001",
		Severity:    "高风险",
		Title:       "恶意代码与破坏性行为",
		Description: "检测到 1 条行为证据，已提取关键样本用于自动复核。",
		Location:    "行为证据采集",
		CodeSnippet: "行为证据摘要: 检测到 1 条行为证据，已提取关键样本用于自动复核。",
	}}
	structured := buildStructuredFindings(findings, review.Result{}, nil, "", nil)
	_, _, integrity := enforceReportConsistency(findings, baseScanOutput{}, review.Result{StructuredFindings: structured})
	for _, issue := range integrity.Issues {
		if strings.Contains(issue, "原始风险未映射到结构化 finding") {
			t.Fatalf("expected filtered summary-only finding ignored for mapping count, got %+v", integrity)
		}
	}
}

func TestEnforceReportConsistencyMapsLegacyAndPublicRuleIDs(t *testing.T) {
	findings := []plugins.Finding{{
		PluginName:  "SecurityEngine",
		RuleID:      "V7-003",
		Severity:    "高风险",
		Title:       "敏感数据外发与隐蔽通道",
		Description: "存在未声明外联",
		Location:    "agent.py:42",
		CodeSnippet: `requests.post(webhook_url, json=payload)`,
	}}
	structured := []review.StructuredFinding{{
		ID:       "SF-001",
		RuleID:   "S2-P0-006",
		Title:    "敏感数据外发与隐蔽通道",
		Category: "外联与情报",
		Evidence: []string{"agent.py:42 requests.post(webhook_url, json=payload)"},
	}}

	_, _, integrity := enforceReportConsistency(findings, baseScanOutput{}, review.Result{StructuredFindings: structured})
	for _, issue := range integrity.Issues {
		if strings.Contains(issue, "原始风险未映射到结构化 finding") {
			t.Fatalf("expected legacy and public rule IDs to map, got %+v", integrity)
		}
	}
}

func TestEnforceReportConsistencyMapsFindingByEvidenceOverlap(t *testing.T) {
	findings := []plugins.Finding{{
		PluginName:  "SecurityEngine",
		RuleID:      "CUSTOM-SSRF-001",
		Severity:    "中风险",
		Title:       "用户可控 URL 请求",
		Description: "target_url 来自 request.json 并进入 requests.get",
		Location:    "client.py:88",
		CodeSnippet: `requests.get(target_url, timeout=5)`,
	}}
	structured := []review.StructuredFinding{{
		ID:       "SF-001",
		RuleID:   "S2-P1-012",
		Title:    "SSRF-内网探测",
		Category: "网络请求与SSRF",
		Evidence: []string{"client.py:88 requests.get(target_url, timeout=5)"},
		EvidenceItems: []review.StructuredEvidenceItem{{
			Location: "client.py:88",
			Snippet:  `requests.get(target_url, timeout=5)`,
			Summary:  "target_url 来自 request.json",
		}},
	}}

	_, _, integrity := enforceReportConsistency(findings, baseScanOutput{}, review.Result{StructuredFindings: structured})
	for _, issue := range integrity.Issues {
		if strings.Contains(issue, "原始风险未映射到结构化 finding") {
			t.Fatalf("expected evidence overlap to map raw finding, got %+v", integrity)
		}
	}
}

func TestEnforceReportConsistencyMergesDuplicateStructuredFindingsAndVerdicts(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:                 "SF-001",
			RuleID:             "V7-003",
			Title:              "仪表板未鉴权暴露",
			Severity:           "高风险",
			Category:           "暴露面与未鉴权服务",
			Confidence:         "高",
			SecurityVerdict:    "review",
			DeclarationVerdict: "declared",
			CodeEvidenceRefs:   []string{"dashboard.py:10 app.run(host=\"0.0.0.0\")"},
			Evidence:           []string{"dashboard.py:10 app.run(host=\"0.0.0.0\")"},
			Source:             "Static",
			DeduplicatedCount:  1,
		}, {
			ID:                  "SF-002",
			RuleID:              "V7-003",
			Title:               "仪表板未鉴权暴露",
			Severity:            "中风险",
			Category:            "暴露面与未鉴权服务",
			Confidence:          "中",
			SecurityVerdict:     "confirmed",
			DeclarationVerdict:  "undeclared",
			ContextEvidenceRefs: []string{"Flask 仪表板未提及认证机制"},
			Evidence:            []string{"Flask 仪表板未提及认证机制"},
			Source:              "LLM",
			DeduplicatedCount:   1,
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "needs_manual_review", Reviewer: "deterministic-vuln-reviewer"}, {FindingID: "SF-002", Verdict: "confirmed", Reviewer: "llm-vuln-reviewer"}},
	}
	_, adjusted, integrity := enforceReportConsistency(nil, baseScanOutput{}, refined)
	if len(adjusted.StructuredFindings) != 1 {
		t.Fatalf("expected duplicate structured findings merged, got %+v", adjusted.StructuredFindings)
	}
	merged := adjusted.StructuredFindings[0]
	if merged.DeduplicatedCount != 2 {
		t.Fatalf("expected deduplicated count summed, got %+v", merged)
	}
	if merged.DeclarationVerdict != "undeclared" {
		t.Fatalf("expected declaration verdict tightened to undeclared, got %+v", merged)
	}
	if !strings.Contains(merged.Source, "Static") || !strings.Contains(merged.Source, "LLM") {
		t.Fatalf("expected merged source labels retained, got %+v", merged)
	}
	if len(adjusted.ReviewAgentVerdicts) != 2 {
		t.Fatalf("expected verdicts remapped onto merged finding id, got %+v", adjusted.ReviewAgentVerdicts)
	}
	for _, verdict := range adjusted.ReviewAgentVerdicts {
		if verdict.FindingID != merged.ID {
			t.Fatalf("expected verdict remapped to merged finding id, got %+v", adjusted.ReviewAgentVerdicts)
		}
	}
	if !containsString(integrity.AutoFixes, "已自动合并 1 组重复主风险") {
		t.Fatalf("expected duplicate merge autofix recorded, got %+v", integrity)
	}
}
