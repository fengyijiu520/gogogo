package handler

import (
	"skill-scanner/internal/llm"
	"slices"
	"strings"
	"testing"

	"skill-scanner/internal/review"
)

func TestExecuteDeterministicReviewAgentProducesThreeVerdicts(t *testing.T) {
	refined := review.Result{StructuredFindings: []review.StructuredFinding{{ID: "SF-001", RuleID: "V7-009", Title: "命令执行", Severity: "高风险", Category: "命令执行", Confidence: "高", AttackPath: "下载后执行", Evidence: []string{"scripts/run.py:10"}, CalibrationBasis: []string{"高危时序"}, ReviewGuidance: "移除 shell 拼接"}, {ID: "SF-002", RuleID: "V7-003", Title: "示例外联", Severity: "中风险", Category: "外联与情报", Confidence: "待复核", AttackPath: "example request", Evidence: []string{"examples/demo.py:1"}, ReviewGuidance: "确认是否发布"}, {ID: "SF-003", RuleID: "V7-004", Title: "凭据访问", Severity: "中风险", Category: "凭据访问", Confidence: "待复核", ReviewGuidance: "补齐证据"}}, FalsePositiveReviews: []review.FalsePositiveReview{{FindingID: "SF-001", Verdict: "倾向真实风险", EvidenceStrength: "强", ReachabilityChecks: []string{"入口可达"}}, {FindingID: "SF-002", Verdict: "疑似误报", EvidenceStrength: "弱", ReachabilityChecks: []string{"已确认示例文件不会进入发布包"}}, {FindingID: "SF-003", Verdict: "待人工复核", EvidenceStrength: "弱"}}}
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
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-001"}, finding, fp, review.Result{Behavior: review.BehaviorProfile{BehaviorChains: []string{"scripts/run.py:10-12 | 下载=1, 落地=0, 执行=1, 外联=0, 持久化=0, 提权=0, 凭据访问=0, 防御规避=0, 横向移动=0, 收集打包=0, C2信标=0"}, SequenceAlerts: []string{"命中下载后执行时序"}}})
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

func TestDeterministicVerdictConfirmsPolicyTIFindingWithoutAttackChain(t *testing.T) {
	finding := review.StructuredFinding{ID: "SF-001", RuleID: "V7-003", Title: "命中黑名单目标（域名/IP）", Severity: "中风险", Category: "外联与情报", Confidence: "中", AttackPath: "访问策略禁止目标", Evidence: []string{"目标证据: https://clob.polymarket.com\n判定依据: 命中公司黑名单目标（域名/IP）"}, ReviewGuidance: "替换为合规目标"}
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
	finding := review.StructuredFinding{ID: "SF-001", RuleID: "V7-015", Title: "说明文档中的远程执行描述", Severity: "中风险", Category: "声明与行为差异", AttackPath: "docs note", Evidence: []string{"docs/guide.md:8 tool supports remote execution"}}
	fp := review.FalsePositiveReview{FindingID: "SF-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。", ReachabilityChecks: []string{"确认风险代码所在文件是否属于技能发布包和主执行路径。"}}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected documentation-only finding downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesInternalDevelopmentFinding(t *testing.T) {
	finding := review.StructuredFinding{ID: "SF-001", RuleID: "V7-003", Title: "本地开发回调地址", Severity: "中风险", Category: "外联与情报", AttackPath: "dev callback", Evidence: []string{"config/dev.yaml:8 callback=http://localhost:3000/api"}}
	fp := review.FalsePositiveReview{FindingID: "SF-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。", ReachabilityChecks: []string{"确认风险代码所在文件是否属于技能发布包和主执行路径。"}}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected internal-development finding downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictConfirmsModerateEvidenceWithRelatedBehavior(t *testing.T) {
	finding := review.StructuredFinding{ID: "SF-001", RuleID: "V7-004", Title: "凭据访问", Severity: "高风险", Category: "凭据访问", AttackPath: "读取凭据后外联", Evidence: []string{"auth.py:8 open('/root/.netrc')"}, CalibrationBasis: []string{"存在与当前风险相关的高危时序告警"}}
	fp := review.FalsePositiveReview{FindingID: "SF-001", Verdict: "待人工复核", EvidenceStrength: "中: 有定位或校准依据，但仍需补充入口可达性。", ReachabilityChecks: []string{"确认风险代码所在文件是否属于技能发布包和主执行路径。"}}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-001"}, finding, fp, review.Result{Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中凭据访问后外联时序"}}})
	if verdict.Verdict != "confirmed" {
		t.Fatalf("expected moderate evidence with related behavior to be confirmed, got %+v", verdict)
	}
	if verdict.Confidence != "高" {
		t.Fatalf("expected high confidence after direct confirmation, got %+v", verdict)
	}
}

func TestDeterministicVerdictAutoSuppliesReachabilityForStrongClosure(t *testing.T) {
	finding := review.StructuredFinding{ID: "SF-AUTO-REACH", RuleID: "V7-003", Title: "敏感外联", Severity: "高风险", Category: "外联与情报", AttackPath: "读取凭据后 requests.post 外发", Evidence: []string{"auth.py:8 token = os.getenv('TOKEN')", "client.py:22 requests.post(target, json={'token': token})"}, CalibrationBasis: []string{"关键样本显示外联", "真实请求和可控目标"}}
	fp := review.FalsePositiveReview{FindingID: "SF-AUTO-REACH", Verdict: "待人工复核", EvidenceStrength: "强: 多源证据或行为链可互相印证。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-AUTO-REACH"}, finding, fp, review.Result{Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中凭据访问后外联时序"}}})
	if verdict.Verdict != "confirmed" {
		t.Fatalf("expected strong closure finding confirmed without explicit reachability checks, got %+v", verdict)
	}
	if slices.Contains(verdict.MissingEvidence, "缺少可达性检查结论") {
		t.Fatalf("expected auto reachability support to remove missing reachability, got %+v", verdict)
	}
}

func TestDeterministicVerdictConfirmsCrossFileRuntimeOnlyGap(t *testing.T) {
	finding := review.StructuredFinding{
		ID:               "SF-XFILE-001",
		RuleID:           "V7-003",
		Title:            "敏感外联",
		Severity:         "高风险",
		Category:         "外联与情报",
		AttackPath:       "读取 token 后 requests.post 外发",
		Evidence:         []string{"auth.py:8 token = os.getenv('TOKEN')", "client.py:22 requests.post(target, json={'token': token})"},
		CalibrationBasis: []string{"跨文件链路研判: 已识别 source 与 sink 分散在不同文件的组合信号，仍需补 runtime 或 transform 支撑。", "关键样本显示外联"},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-XFILE-001", Verdict: "待人工复核", EvidenceStrength: "中: 有定位或校准依据，但仍需补充入口可达性。"}
	refined := review.Result{CrossFileConsolidation: &llm.CrossFileConsolidation{RelatedCategories: []string{"外联与情报"}, MissingParts: []string{"runtime"}}}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-XFILE-001"}, finding, fp, refined)
	if verdict.Verdict != "confirmed" {
		t.Fatalf("expected cross-file runtime-only gap to be auto-confirmed, got %+v", verdict)
	}
	if slices.Contains(verdict.MissingEvidence, "缺少运行链路或行为支撑") || slices.Contains(verdict.MissingEvidence, "缺少可达性检查结论") {
		t.Fatalf("expected cross-file deterministic support to remove runtime/reachability gaps, got %+v", verdict.MissingEvidence)
	}
}

func TestDeterministicVerdictKeepsManualReviewWhenCrossFileStillMissingSource(t *testing.T) {
	finding := review.StructuredFinding{
		ID:               "SF-XFILE-002",
		RuleID:           "V7-003",
		Title:            "可疑外联",
		Severity:         "高风险",
		Category:         "外联与情报",
		AttackPath:       "读取 target 后外发",
		Evidence:         []string{"client.py:22 requests.post(target, json=payload)"},
		CalibrationBasis: []string{"跨文件链路研判: 已识别 source 与 sink 分散在不同文件的组合信号，仍需补 runtime 或 transform 支撑。"},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-XFILE-002", Verdict: "待人工复核", EvidenceStrength: "中: 有定位或校准依据，但仍需补充入口可达性。"}
	refined := review.Result{CrossFileConsolidation: &llm.CrossFileConsolidation{RelatedCategories: []string{"外联与情报"}, MissingParts: []string{"source", "runtime"}}}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-XFILE-002"}, finding, fp, refined)
	if verdict.Verdict != "needs_manual_review" {
		t.Fatalf("expected missing source to keep manual review, got %+v", verdict)
	}
}

func TestBuildFindingClosureSummaryRequiresSourceAndSinkForCommandExecution(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-CMD-001",
		Title:      "命令执行",
		Category:   "命令执行",
		AttackPath: "payload 进入 subprocess 执行",
		Evidence:   []string{"scripts/run.py:18 subprocess.run(payload, shell=True)"},
	}
	closure := buildFindingClosureSummary(finding, review.Result{Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中下载后执行时序"}}})
	if !closure.HasSource || !closure.HasSink || !closure.HasRuntimeSupport {
		t.Fatalf("expected closure to detect source/sink/runtime, got %+v", closure)
	}
}

func TestBuildFindingClosureSummaryClassifiesGenericEvidenceRoles(t *testing.T) {
	finding := review.StructuredFinding{
		ID:               "SF-GENERIC-001",
		Title:            "跨文件外联链路",
		Category:         "外联与情报",
		AttackPath:       "配置进入 payload 后外发",
		Evidence:         []string{"输入来源=request.json target_url", "payload = {'token': token}"},
		CodeEvidenceRefs: []string{"client.py:42 requests.post(webhook, json=payload)"},
		EvidenceItems: []review.StructuredEvidenceItem{
			{Location: "client.py:40", Snippet: "webhook = os.getenv('WEBHOOK_URL')", SourceType: "plugin_finding"},
		},
		BehaviorEvidenceRefs: []string{"runtime=http_probe scenario=default exit=0"},
	}
	closure := buildFindingClosureSummary(finding, review.Result{})
	if !closure.HasSource || !closure.HasTransform || !closure.HasSink || !closure.HasRuntimeSupport {
		t.Fatalf("expected generic evidence roles to fill closure, got %+v", closure)
	}
}

func TestDeterministicVerdictKeepsManualReviewWithoutClosureSink(t *testing.T) {
	finding := review.StructuredFinding{
		ID:               "SF-EXT-001",
		RuleID:           "V7-003",
		Title:            "可疑外联",
		Severity:         "高风险",
		Category:         "外联与情报",
		Confidence:       "高",
		AttackPath:       "读取 target url",
		Evidence:         []string{"client.py:12 target = config['url']"},
		CalibrationBasis: []string{"存在外联配置"},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-EXT-001", Verdict: "倾向真实风险", EvidenceStrength: "强", ReachabilityChecks: []string{"确认风险代码所在文件是否属于技能发布包和主执行路径。"}}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-EXT-001"}, finding, fp, review.Result{Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中可疑外联时序"}}})
	if verdict.Verdict != "needs_manual_review" {
		t.Fatalf("expected missing sink evidence to keep manual review, got %+v", verdict)
	}
	if !slices.Contains(verdict.MissingEvidence, "缺少链路落点/sink 证据") {
		t.Fatalf("expected missing sink evidence in verdict, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesOpenWeakDependencyFinding(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-DEP-001",
		RuleID:     "V7-016",
		Title:      "依赖漏洞与恶意依赖-高危漏洞依赖",
		Severity:   "中风险",
		Category:   "静态规则发现",
		Confidence: "中",
		Evidence:   []string{"requirements.txt 中存在高危依赖提示", "建议结合 SBOM 与运行路径继续核验"},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-DEP-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-DEP-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected open weak dependency finding downgraded, got %+v", verdict)
	}
	if verdict.Confidence != "中高" {
		t.Fatalf("expected medium-high confidence, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesOpenWeakPrivacyFinding(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-PII-001",
		RuleID:     "V7-019",
		Title:      "隐私合规与数据最小化-过度收集个人信息",
		Severity:   "中风险",
		Category:   "隐私合规与数据最小化",
		Confidence: "中",
		Evidence:   []string{"表单字段较多，需结合真实提交与用途核验", "当前仅有规则侧建议补充数据流与告知链路"},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-PII-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-PII-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected open weak privacy finding downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesPrivacyFindingWhenEvidenceShowsIntentMismatch(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-PII-002",
		RuleID:     "V7-019",
		Title:      "隐私合规与数据最小化-过度收集个人信息",
		Severity:   "中风险",
		Category:   "隐私合规与数据最小化",
		Confidence: "中",
		AttackPath: "get_config 调用",
		Evidence: []string{
			"polymarket.py:45 get_config(config_path)",
			"未发现递归调用，get_config 只是普通文件读取，规则主题与证据不匹配",
		},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-PII-002", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-PII-002"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected privacy intent mismatch downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesWhenExclusionChecksRefutePrimaryClaim(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-EXCLUSION-001",
		RuleID:     "V7-014",
		Title:      "声明与行为差异",
		Severity:   "中风险",
		Category:   "声明与行为差异",
		Confidence: "中",
		Evidence:   []string{"templates/index.html:1 纯 HTML 模板页面"},
	}
	fp := review.FalsePositiveReview{
		FindingID:        "SF-EXCLUSION-001",
		Verdict:          "待人工复核",
		EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。",
		ExclusionChecks:  []string{"没有代码实现，无网络暴露，仅属于文档质量问题", "确认该文件不会进入动态执行链路"},
	}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-EXCLUSION-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected exclusion checks to refute primary claim and downgrade, got %+v", verdict)
	}
	if verdict.Confidence != "中高" {
		t.Fatalf("expected medium-high confidence for exclusion-based downgrade, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesTemplateOnlyExposureMismatch(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-DECL-001",
		RuleID:     "V7-014",
		Title:      "声明与行为差异",
		Severity:   "中风险",
		Category:   "声明与行为差异",
		Confidence: "中",
		Evidence: []string{
			"templates/index.html:1 纯 HTML 模板页面",
			"没有代码实现，无网络暴露，仅属于文档质量问题",
		},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-DECL-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-DECL-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected template-only declaration mismatch downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesSmokeImportDeclarationMismatch(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-DECL-SMOKE-001",
		RuleID:     "LLM-DETECT",
		Title:      "核心模块未经审查，可能存在恶意代码",
		Severity:   "中风险",
		Category:   "声明与行为差异",
		Confidence: "中",
		AttackPath: "声明与实际行为存在偏差",
		Evidence: []string{
			"test_smoke.py: import scripts.polymarket as sniper",
			"位置: test_smoke.py",
		},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-DECL-SMOKE-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-DECL-SMOKE-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected smoke import declaration mismatch downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesDeclarationOnlyDataCollectionClaim(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-DECL-DATA-001",
		RuleID:     "S2-P1-031",
		Title:      "隐私合规与数据最小化-过度收集个人信息",
		Severity:   "低风险",
		Category:   "声明与行为差异",
		Confidence: "中",
		AttackPath: "技能声明与实际行为存在偏差",
		Evidence: []string{
			"位置: 技能声明与数据收集行为对照",
		},
		ContextEvidenceRefs: []string{
			"技能声明与数据收集行为对照 声明收集数据: 凭据、邮箱、地址、姓名、设备标识",
		},
	}
	fp := review.FalsePositiveReview{
		FindingID:        "SF-DECL-DATA-001",
		Verdict:          "待人工复核",
		EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。",
		ExclusionChecks:  []string{"文档或示例证据不进入主证据集", "插件命中位于文档、示例或内部开发语境"},
	}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-DECL-DATA-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected declaration-only data collection claim downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesComplianceOnlyExposureClaim(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-COMP-001",
		RuleID:     "V7-013",
		Title:      "功能完全缺失且存在恶意诱骗风险",
		Severity:   "中风险",
		Category:   "暴露面与未鉴权服务",
		Confidence: "中",
		Evidence: []string{
			"__init__.py:1 # (empty) - make scripts a package",
			"功能缺失属于完整性或合规问题，不构成可利用的安全漏洞，且分类与证据不符",
		},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-COMP-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-COMP-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected compliance-only exposure claim downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesRefutedInfiniteLoopClaim(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-LOOP-001",
		RuleID:     "V7-023",
		Title:      "资源耗尽与级联失败-无限循环/无超时",
		Severity:   "低风险",
		Category:   "静态规则发现",
		Confidence: "中",
		AttackPath: "检测到 get_config 递归调用",
		Evidence: []string{
			"polymarket.py:48 def get_config():",
			"未发现递归调用，该主张与代码事实不符",
			"requests.get 未统一设置 timeout，但当前缺少主流程 runtime 证据",
		},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-LOOP-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-LOOP-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected refuted infinite-loop claim downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesAuditClaimWithExistingAuditContext(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-AUDIT-001",
		RuleID:     "S2-P1-023",
		Title:      "日志审计与敏感信息脱敏-关键事件无审计",
		Severity:   "低风险",
		Category:   "静态规则发现",
		Confidence: "中",
		Evidence: []string{
			"dashboard.py:22 logger.audit('webhook dispatched', extra={'result': 'ok'})",
			"已有审计日志，主张与代码事实不符",
		},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-AUDIT-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-AUDIT-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected audit claim with existing audit context downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesSQLiteReadOnlyDataMinimizationClaim(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-SQLITE-001",
		RuleID:     "S2-P1-031",
		Title:      "隐私合规与数据最小化-过度收集个人信息",
		Severity:   "低风险",
		Category:   "隐私合规与数据最小化",
		Confidence: "中",
		Evidence: []string{
			"db.py:12 conn = sqlite3.connect(DB_NAME)",
			"db.py:13 rows = conn.execute('SELECT session FROM positions').fetchall()",
			"仅本地 SQLite 读取，当前缺少外发或暴露链路",
		},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-SQLITE-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-SQLITE-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected sqlite read-only minimization claim downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesConfigWebhookSSRFMismatch(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-SSRF-CONFIG-001",
		RuleID:     "S2-P1-012",
		Title:      "SSRF-内网探测",
		Severity:   "中风险",
		Category:   "网络请求与SSRF",
		Confidence: "中",
		AttackPath: "webhook 来自配置并进入 requests.post",
		Evidence: []string{
			"polymarket.py:56 webhook = config.get(\"discord_webhook\")",
			"polymarket.py:59 requests.post(webhook, json={\"content\": msg})",
			"来源类型=config_value",
		},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-SSRF-CONFIG-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-SSRF-CONFIG-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected config webhook ssrf mismatch downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesLicenseLocalFallbackWithoutFailOpen(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-LICENSE-LOCAL-001",
		RuleID:     "LLM-DETECT",
		Title:      "授权绕过风险 - 许可证校验逻辑不闭环",
		Severity:   "低风险",
		Category:   "授权与许可证校验",
		Confidence: "中",
		AttackPath: "LICENSE_SERVER 默认指向 localhost:8080",
		Evidence: []string{
			"polymarket.py:16 LICENSE_SERVER = os.getenv(\"LICENSE_SERVER\", \"http://localhost:8080\")",
			"polymarket.py:20 if not PRO_LICENSE_KEY: return False",
		},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-LICENSE-LOCAL-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-LICENSE-LOCAL-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected localhost license fallback downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictKeepsManualReviewForExposureSinkWithConcreteLocation(t *testing.T) {
	finding := review.StructuredFinding{
		ID:               "SF-EXP-001",
		RuleID:           "V7-009",
		Title:            "仪表板监听所有网络接口且无身份认证",
		Severity:         "高风险",
		Category:         "暴露面与未鉴权服务",
		Confidence:       "中",
		AttackPath:       "dashboard app.run 暴露服务",
		Evidence:         []string{"dashboard.py:88 app.run(host='0.0.0.0', port=5000)"},
		CodeEvidenceRefs: []string{"dashboard.py:88 app.run(host='0.0.0.0', port=5000)"},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-EXP-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-EXP-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "needs_manual_review" {
		t.Fatalf("expected concrete exposure sink to stay manual review, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesTemplateAutoescapeExposureMismatch(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-XSS-TEMPLATE-001",
		RuleID:     "LLM-DETECT",
		Title:      "仪表盘模板可能缺少输出转义导致跨站脚本（XSS）",
		Severity:   "中风险",
		Category:   "暴露面与未鉴权服务",
		Confidence: "中",
		AttackPath: "Jinja 模板变量直接输出",
		Evidence: []string{
			"templates/index.html:12 <td>{{ log['message'] }}</td>",
			"纯 HTML 模板页面，autoescape 默认开启，无网络暴露",
		},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-XSS-TEMPLATE-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-XSS-TEMPLATE-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected template autoescape exposure mismatch downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesDependencyAdvisoryOnlyFinding(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-DEP-ADVISORY-001",
		RuleID:     "S2-P1-004",
		Title:      "依赖漏洞与恶意依赖-高危漏洞依赖",
		Severity:   "中风险",
		Category:   "环境与构建风险",
		Confidence: "中",
		Evidence: []string{
			"建议补充依赖清单并锁定版本。",
			"缺少版本信息，无法完成漏洞精确比对。",
		},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-DEP-ADVISORY-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-DEP-ADVISORY-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected dependency advisory-only finding downgraded, got %+v", verdict)
	}
}

func TestEvidenceTierDowngradesStrongEvidenceWithoutClosure(t *testing.T) {
	finding := review.StructuredFinding{
		ID:                "SF-TIER-001",
		RuleID:            "V7-003",
		Title:             "可疑外联",
		Severity:          "高风险",
		Category:          "外联与情报",
		Confidence:        "高",
		Evidence:          []string{"sync.py:2 target = config['webhook']"},
		CalibrationBasis:  []string{"存在外联配置", "同类证据命中 2 次，已合并展示"},
		DeduplicatedCount: 2,
	}
	tier := evidenceTierForFinding(finding, review.ReviewAgentVerdict{FindingID: "SF-TIER-001", Verdict: "needs_manual_review", Confidence: "高"}, review.Result{})
	if tier != evidenceTierModerate {
		t.Fatalf("expected strong-looking but non-closure finding downgraded to moderate, got %s", tier)
	}
}

func TestFalsePositiveVerdictRequiresClosureForStrongRiskBias(t *testing.T) {
	finding := review.StructuredFinding{
		ID:       "SF-FP-001",
		RuleID:   "V7-003",
		Title:    "可疑外联",
		Severity: "高风险",
		Category: "外联与情报",
		Evidence: []string{"sync.py:2 target = config['webhook']"},
	}
	item := review.FalsePositiveReview{
		FindingID:        "SF-FP-001",
		EvidenceStrength: "强: 多源证据或行为链可互相印证。",
		Exploitability:   "较高: 存在行为链或高危时序证据，可支持攻击路径复核。",
	}
	verdict := falsePositiveVerdict(item, finding, review.Result{})
	if !strings.Contains(verdict, "待人工复核") {
		t.Fatalf("expected no closure to keep manual review, got %s", verdict)
	}
}

func TestDeterministicVerdictDowngradesWeakEnvironmentRiskToLikelyFalsePositive(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-ENV-001",
		RuleID:     "V7-022",
		Title:      "Python 系统包安装风险",
		Severity:   "低风险",
		Category:   "环境与构建风险",
		AttackPath: "bootstrap 安装依赖",
		Evidence:   []string{"bootstrap.sh:23 pip3 install -r requirements.txt --break-system-packages"},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-ENV-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。", ReachabilityChecks: []string{"确认风险代码所在文件是否属于技能发布包和主执行路径。"}}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-ENV-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected weak environment risk downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesWeakStaticFindingWithoutClosure(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-STATIC-001",
		RuleID:     "V7-019",
		Title:      "隐藏风险内容-代码混淆隐藏",
		Severity:   "低风险",
		Category:   "静态规则发现",
		AttackPath: "可能存在隐藏内容",
		Evidence:   []string{"README.md: 未定位到具体行，请检查是否存在混淆代码或高熵数据"},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-STATIC-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。", ReachabilityChecks: []string{"确认风险代码所在文件是否属于技能发布包和主执行路径。"}}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-STATIC-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected weak static finding downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictDowngradesContextOnlyManualFinding(t *testing.T) {
	finding := review.StructuredFinding{
		ID:                  "SF-CONTEXT-ONLY-001",
		RuleID:              "S2-P1-012",
		Title:               "SSRF-内网探测",
		Severity:            "中风险",
		Category:            "网络请求与SSRF",
		AttackPath:          "上下文提示目标可能可控",
		Evidence:            []string{"目标证据: 用户配置可能包含 URL"},
		ContextEvidenceRefs: []string{"输入来源=url", "来源类型=config_value"},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-CONTEXT-ONLY-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-CONTEXT-ONLY-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected context-only finding downgraded, got %+v", verdict)
	}
}

func TestDeterministicVerdictAddsManualReviewTriageLabel(t *testing.T) {
	finding := review.StructuredFinding{
		ID:               "SF-MANUAL-TRIAGE-001",
		RuleID:           "V7-009",
		Title:            "命令执行需复核",
		Severity:         "高风险",
		Category:         "命令执行",
		AttackPath:       "执行调用存在但入口来源仍需确认",
		Evidence:         []string{"agent.py:22 subprocess.run(static_args)"},
		CodeEvidenceRefs: []string{"agent.py:22 subprocess.run(static_args)"},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-MANUAL-TRIAGE-001", Verdict: "待人工复核", EvidenceStrength: "中: 有定位或校准依据，但仍需补充入口可达性。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-MANUAL-TRIAGE-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "needs_manual_review" {
		t.Fatalf("expected finding remains manual review, got %+v", verdict)
	}
	if !strings.Contains(strings.Join(verdict.MissingEvidence, "\n"), "复核分流:") {
		t.Fatalf("expected manual triage label in missing evidence, got %+v", verdict.MissingEvidence)
	}
}

func TestManualReviewBucketsUseTriageLabel(t *testing.T) {
	ctx := newReviewedFindingContext(review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:                  "SF-001",
			Title:               "SSRF-内网探测",
			Category:            "网络请求与SSRF",
			Evidence:            []string{"目标证据: 用户配置可能包含 URL"},
			ContextEvidenceRefs: []string{"输入来源=url"},
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{
			FindingID:       "SF-001",
			Verdict:         "needs_manual_review",
			MissingEvidence: []string{"复核分流: 可机审降级-仅上下文证据"},
		}},
	})
	buckets := ctx.manualReviewBuckets()
	if len(buckets) != 1 || !strings.Contains(buckets[0], "可机审降级-仅上下文证据") {
		t.Fatalf("expected triage label bucket, got %+v", buckets)
	}
}

func TestDeterministicVerdictKeepsManualReviewForExposureFindingWithRealSink(t *testing.T) {
	finding := review.StructuredFinding{
		ID:         "SF-EXPOSURE-001",
		RuleID:     "V7-020",
		Title:      "未授权访问导致敏感交易数据泄露",
		Severity:   "中风险",
		Category:   "暴露面与未鉴权服务",
		AttackPath: "dashboard 对外监听",
		Evidence:   []string{"dashboard.py:22 app.run(host='0.0.0.0', port=5000)"},
	}
	fp := review.FalsePositiveReview{FindingID: "SF-EXPOSURE-001", Verdict: "待人工复核", EvidenceStrength: "弱: 证据不足，应优先人工复核并补充运行链路。", ReachabilityChecks: []string{"确认风险代码所在文件是否属于技能发布包和主执行路径。"}}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-EXPOSURE-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "needs_manual_review" {
		t.Fatalf("expected exposure finding with real sink stay manual review, got %+v", verdict)
	}
	if slices.Contains(verdict.MissingEvidence, "缺少链路落点/sink 证据") {
		t.Fatalf("expected sink already present for exposure finding, got %+v", verdict.MissingEvidence)
	}
}
