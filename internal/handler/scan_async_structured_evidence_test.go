package handler

import (
	"strings"
	"testing"

	"skill-scanner/internal/evaluator"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func TestBuildStructuredFindingsIgnoresUnrelatedBehaviorSupport(t *testing.T) {
	findings := []plugins.Finding{{PluginName: "Static", RuleID: "V7-006", Severity: "高风险", Title: "凭据访问", Description: "检测到凭据读取", Location: "scripts/auth.py:8", CodeSnippet: "open('.env').read()"}}
	structured := buildStructuredFindings(findings, review.Result{Behavior: review.BehaviorProfile{
		BehaviorChains: []string{"scripts/run.py:10-12 | 下载=1, 落地=0, 执行=1, 外联=0, 持久化=0, 提权=0, 凭据访问=0, 防御规避=0, 横向移动=0, 收集打包=0, C2信标=0"},
		SequenceAlerts: []string{"命中下载后执行时序"},
	}}, nil, "", nil)
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

func TestBuildStructuredFindingsAddsHTTPProbeRuntimeEvidence(t *testing.T) {
	findings := []plugins.Finding{{PluginName: "Static", RuleID: "V7-003", Severity: "中风险", Title: "外联风险", Description: "检测到外联处理入口", Location: "app.py:22", CodeSnippet: "requests.post(url, data=payload)"}}
	structured := buildStructuredFindings(findings, review.Result{Behavior: review.BehaviorProfile{
		ScenarioExecutions: []review.ScenarioExecution{{
			Name:           "python-app-http-probe",
			Command:        "python3 app.py",
			HTTPMethod:     "POST",
			HTTPPort:       8080,
			HTTPPath:       "/submit",
			HTTPStatusCode: 200,
			Output:         []string{"http_probe method=POST port=8080 path=/submit status=200 body_sha256=abc123def456 body_sample={\"ok\":true}"},
		}},
	}}, nil, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected single structured finding, got %+v", structured)
	}
	item := structured[0]
	joinedChains := strings.Join(item.ChainSummaries, "\n")
	for _, want := range []string{"HTTP探针", "body_sha256=abc123def456", "body_sample={\"ok\":true}"} {
		if !strings.Contains(joinedChains, want) {
			t.Fatalf("expected runtime token %s in chain summaries, got %+v", want, item.ChainSummaries)
		}
	}
	joinedBehaviorRefs := strings.Join(item.BehaviorEvidenceRefs, "\n")
	if !strings.Contains(joinedBehaviorRefs, "http_probe") || !strings.Contains(joinedBehaviorRefs, "body_sample") {
		t.Fatalf("expected http probe behavior refs, got %+v", item.BehaviorEvidenceRefs)
	}
	if !item.Closure.RuntimeSupport {
		t.Fatalf("expected runtime closure support, got %+v", item.Closure)
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
		{PluginName: "BehaviorGuard", RuleID: "V7-009", Severity: "高风险", Title: "自更新与远程下载执行", Description: "检测到 2 条行为证据，已提取关键样本用于自动复核。", Location: "行为证据采集", CodeSnippet: "行为证据摘要: 检测到 2 条行为证据，已提取关键样本用于自动复核。"},
	}
	structured := buildStructuredFindings(findings, review.Result{Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中下载后执行时序"}}}, nil, "", nil)
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

func TestDeclarationSubtypeLabelClassifiesDeclarationMismatchCards(t *testing.T) {
	if got := declarationSubtypeLabel(review.StructuredFinding{Category: "声明与行为差异", Evidence: []string{"polymarket.py:16 LICENSE_SERVER = os.getenv(\"LICENSE_SERVER\", \"http://localhost:8080\")"}}); got != "网络访问" {
		t.Fatalf("expected declaration network subtype, got %q", got)
	}
	if got := declarationSubtypeLabel(review.StructuredFinding{Category: "声明与行为差异", Evidence: []string{"polymarket.py:50 wallet_private_key = \"\""}}); got != "凭据处理" {
		t.Fatalf("expected declaration credential subtype, got %q", got)
	}
}

func TestStructuredFindingEvidenceExpandsRiskClusterWindow(t *testing.T) {
	files := []evaluator.SourceFile{{Path: "/tmp/demo/scripts/run.py", Content: strings.Join([]string{
		"line1()",
		"danger_a()",
		"line3()",
		"line4()",
		"line5()",
		"line6()",
		"danger_b()",
		"line8()",
		"line9()",
		"line10()",
	}, "\n")}}
	evidence := structuredFindingEvidence([]plugins.Finding{
		{RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Location: "scripts/run.py:2", CodeSnippet: "danger_a()"},
		{RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Location: "scripts/run.py:7", CodeSnippet: "danger_b()"},
	}, buildSourceContextIndex("/tmp/demo", files))
	if len(evidence) != 1 {
		t.Fatalf("expected clustered code evidence, got %+v", evidence)
	}
	block := evidence[0]
	for _, want := range []string{"scripts/run.py:1-10", ">    2 | danger_a()", ">    7 | danger_b()", "   10 | line10()"} {
		if !strings.Contains(block, want) {
			t.Fatalf("expected clustered block contains %q, got %q", want, block)
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

func TestStructuredFindingEvidenceFiltersLicenseNoise(t *testing.T) {
	findings := []plugins.Finding{
		{PluginName: "Static", RuleID: "V7-005", Severity: "高风险", Title: "授权绕过风险 - 许可证校验逻辑不闭环", Description: "许可证验证使用本地默认服务或明文地址", Location: "polymarket.py:16", CodeSnippet: `LICENSE_SERVER = "http://localhost:8080"`},
		{PluginName: "Static", RuleID: "V7-005", Severity: "高风险", Title: "授权绕过风险 - 许可证校验逻辑不闭环", Description: "许可证验证请求", Location: "polymarket.py:23", CodeSnippet: `resp = requests.post(f"{LICENSE_SERVER}/api/validate")`},
		{PluginName: "Static", RuleID: "V7-005", Severity: "高风险", Title: "授权绕过风险 - 许可证校验逻辑不闭环", Description: "交易 API 请求", Location: "polymarket.py:137", CodeSnippet: `response = requests.get(f"{GAMMA_API}/markets")`},
	}
	evidence := structuredFindingEvidence(findings, nil)
	joined := strings.Join(evidence, "\n")
	if !strings.Contains(joined, "LICENSE_SERVER") || !strings.Contains(joined, "/api/validate") {
		t.Fatalf("expected license evidence retained, got %q", joined)
	}
	if strings.Contains(joined, "GAMMA_API") || strings.Contains(joined, "/markets") {
		t.Fatalf("expected unrelated trading API evidence filtered out, got %q", joined)
	}
}

func TestStructuredFindingEvidenceFiltersOutboundBackgroundNoise(t *testing.T) {
	findings := []plugins.Finding{
		{PluginName: "Static", RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道", Description: "检测到外联", Location: "polymarket.py:59", CodeSnippet: `requests.post(webhook, json={"content": msg})`},
		{PluginName: "Static", RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道", Description: "检测到外联", Location: "polymarket.py:155", CodeSnippet: `res = requests.get(f"{CLOB_API}{path}", headers=headers)`},
		{PluginName: "Static", RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道", Description: "链上只读余额查询", Location: "polymarket.py:126", CodeSnippet: `balance = usdc.functions.balanceOf(acc.address).call()`},
		{PluginName: "Static", RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道", Description: "许可证校验请求", Location: "polymarket.py:23", CodeSnippet: `resp = requests.post(f"{LICENSE_SERVER}/api/validate")`},
	}
	evidence := structuredFindingEvidence(findings, nil)
	joined := strings.Join(evidence, "\n")
	if !strings.Contains(joined, "requests.post") || !strings.Contains(joined, "requests.get") {
		t.Fatalf("expected outbound request evidence retained, got %q", joined)
	}
	if strings.Contains(strings.ToLower(joined), "balanceof") {
		t.Fatalf("expected read-only chain query filtered from outbound evidence, got %q", joined)
	}
	if strings.Contains(joined, "LICENSE_SERVER") || strings.Contains(joined, "/api/validate") {
		t.Fatalf("expected license validation filtered from outbound evidence, got %q", joined)
	}
}

func TestStructuredFindingEvidenceRanksCodeBeforeBehaviorSummary(t *testing.T) {
	findings := []plugins.Finding{
		{PluginName: "BehaviorGuard", RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道", Location: "/tmp/demo/.scan-cache.json:1", CodeSnippet: "行为证据摘要: 检测到 3 条行为证据"},
		{PluginName: "Static", RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道", Location: "scripts/run.py:5", CodeSnippet: "requests.post(url, data)"},
	}
	evidence := structuredFindingEvidence(findings, nil)
	if len(evidence) < 1 {
		t.Fatalf("expected source code evidence, got %+v", evidence)
	}
	if !strings.Contains(evidence[0], "scripts/run.py:5") {
		t.Fatalf("expected source code evidence ranked first, got %+v", evidence)
	}
	if strings.Contains(strings.Join(evidence, "\n"), ".scan-cache.json") {
		t.Fatalf("expected internal scan cache evidence hidden from report, got %+v", evidence)
	}
}

func TestStructuredFindingEvidenceRanksRuntimeCodeBeforeDocumentation(t *testing.T) {
	files := []evaluator.SourceFile{
		{Path: "/tmp/demo/README.md", Content: strings.Join([]string{
			"# Demo Skill",
			"This tool can run requests.post(webhook, data)",
			"Example only",
		}, "\n")},
		{Path: "/tmp/demo/scripts/run.py", Content: strings.Join([]string{
			"def run():",
			"    prepare()",
			"    requests.post(webhook, data)",
			"    return True",
		}, "\n")},
	}
	findings := []plugins.Finding{
		{PluginName: "Static", RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道", Location: "README.md:2", CodeSnippet: "requests.post(webhook, data)", Description: "README 示例提到外联"},
		{PluginName: "Static", RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道", Location: "scripts/run.py:3", CodeSnippet: "requests.post(webhook, data)", Description: "运行代码包含外联"},
	}
	evidence := structuredFindingEvidence(findings, buildSourceContextIndex("/tmp/demo", files))
	if len(evidence) < 2 {
		t.Fatalf("expected code and documentation evidence, got %+v", evidence)
	}
	if !strings.Contains(evidence[0], "scripts/run.py") {
		t.Fatalf("expected runtime code evidence ranked first, got %+v", evidence)
	}
	if !strings.Contains(strings.Join(evidence, "\n"), "README.md") {
		t.Fatalf("expected documentation evidence retained as supplement, got %+v", evidence)
	}
	if strings.Contains(evidence[0], "README.md") {
		t.Fatalf("expected documentation evidence not to outrank runtime code, got %+v", evidence)
	}
}

func TestStructuredFindingEvidenceRanksLicenseAnchorsBeforeGenericConfig(t *testing.T) {
	findings := []plugins.Finding{
		{PluginName: "Static", RuleID: "V7-005", Severity: "高风险", Title: "授权绕过风险 - 许可证校验逻辑不闭环", Description: "许可证验证配置", Location: "licensing.py:8", CodeSnippet: `LICENSE_SERVER = "http://localhost:8080"`},
		{PluginName: "Static", RuleID: "V7-005", Severity: "高风险", Title: "授权绕过风险 - 许可证校验逻辑不闭环", Description: "许可证校验执行", Location: "licensing.py:23", CodeSnippet: `resp = requests.post(f"{LICENSE_SERVER}/api/validate")`},
		{PluginName: "Static", RuleID: "V7-005", Severity: "高风险", Title: "授权绕过风险 - 许可证校验逻辑不闭环", Description: "失败分支可绕过", Location: "licensing.py:31", CodeSnippet: `if verify_failed { return true }`},
	}
	evidence := structuredFindingEvidence(findings, nil)
	if len(evidence) < 2 {
		t.Fatalf("expected multiple license evidence blocks, got %+v", evidence)
	}
	joinedTop := strings.Join(evidence[:2], "\n")
	if !strings.Contains(joinedTop, "/api/validate") && !strings.Contains(joinedTop, "verify_failed") {
		t.Fatalf("expected key license anchors ranked first, got %+v", evidence)
	}
	if strings.Contains(evidence[0], "LICENSE_SERVER") && !strings.Contains(evidence[0], "/api/validate") && !strings.Contains(evidence[0], "verify_failed") {
		t.Fatalf("expected generic config not ranked ahead of stronger anchors, got %+v", evidence)
	}
}

func TestStructuredFindingEvidenceRanksAutoTradingAnchorsBeforeMarketQueries(t *testing.T) {
	findings := []plugins.Finding{
		{PluginName: "Static", RuleID: "LLM-DETECT", Severity: "高风险", Title: "自动交易资金风险需复核", Description: "构建订单参数", Location: "polymarket.py:175", CodeSnippet: `order_args = build_order_args(market)`},
		{PluginName: "Static", RuleID: "LLM-DETECT", Severity: "高风险", Title: "自动交易资金风险需复核", Description: "提交真实订单", Location: "polymarket.py:201", CodeSnippet: `signed_order = self.client.create_order(order_args)`},
		{PluginName: "Static", RuleID: "LLM-DETECT", Severity: "中风险", Title: "自动交易资金风险需复核", Description: "市场查询", Location: "polymarket.py:220", CodeSnippet: `response = requests.get(f"{GAMMA_API}/markets")`},
	}
	evidence := structuredFindingEvidence(findings, nil)
	if len(evidence) < 2 {
		t.Fatalf("expected multiple auto trading evidence blocks, got %+v", evidence)
	}
	joinedTop := strings.Join(evidence[:2], "\n")
	if !strings.Contains(joinedTop, "create_order") {
		t.Fatalf("expected create_order anchor ranked first, got %+v", evidence)
	}
	if strings.Contains(evidence[0], "GAMMA_API") || strings.Contains(evidence[0], "/markets") {
		t.Fatalf("expected market query not to outrank order anchor, got %+v", evidence)
	}
}

func TestStructuredFindingEvidenceMapsBehaviorSummaryBackToSourceAnchors(t *testing.T) {
	files := []evaluator.SourceFile{{Path: "/tmp/demo/scripts/run.py", Content: strings.Join([]string{
		"prepare()",
		"token = os.getenv(\"API_TOKEN\")",
		"requests.post(webhook, json={\"token\": token})",
		"cleanup()",
	}, "\n")}}
	findings := []plugins.Finding{{
		PluginName:  "BehaviorGuard",
		RuleID:      "V7-003",
		Severity:    "高风险",
		Title:       "敏感数据外发与隐蔽通道",
		Description: "检测到 3 条行为证据，已提取关键样本用于自动复核。",
		Location:    "/tmp/demo/.scan-cache.json:1",
		CodeSnippet: "行为证据摘要: 检测到 3 条行为证据，已提取关键样本用于自动复核。",
	}}
	evidence := structuredFindingEvidence(findings, buildSourceContextIndex("/tmp/demo", files))
	if len(evidence) == 0 {
		t.Fatalf("expected mapped behavior evidence, got empty")
	}
	if !strings.Contains(evidence[0], "scripts/run.py:1-4") {
		t.Fatalf("expected source anchor block ranked first, got %+v", evidence)
	}
	if !strings.Contains(evidence[0], "requests.post(webhook") || !strings.Contains(evidence[0], "API_TOKEN") {
		t.Fatalf("expected mapped source anchor includes outbound and credential lines, got %+v", evidence)
	}
	if strings.Contains(strings.Join(evidence, "\n"), ".scan-cache.json") {
		t.Fatalf("expected scan cache summary removed from user visible evidence, got %+v", evidence)
	}
}

func TestBuildStructuredFindingsClassifiesLicenseSeparatelyFromOutbound(t *testing.T) {
	files := []evaluator.SourceFile{{Path: "/tmp/demo/polymarket.py", Content: strings.Join([]string{
		`LICENSE_SERVER = os.getenv("LICENSE_SERVER", "http://localhost:8080")`,
		`PRO_LICENSE_KEY = os.getenv("PRO_LICENSE_KEY", "")`,
		`def validate_pro_license():`,
		`    resp = requests.post(f"{LICENSE_SERVER}/api/validate")`,
		`GAMMA_API = "https://gamma-api.polymarket.com"`,
		`requests.get(f"{GAMMA_API}/markets")`,
	}, "\n")}}
	findings := []plugins.Finding{{
		PluginName:  "SecurityEngine",
		RuleID:      "LLM-DETECT",
		Severity:    "高风险",
		Title:       "授权绕过风险 - 许可证校验逻辑不闭环",
		Description: "许可证校验依赖 http://localhost:8080，需确认失败分支是否可能放行。",
		Location:    "polymarket.py:1",
		CodeSnippet: `LICENSE_SERVER = os.getenv("LICENSE_SERVER", "http://localhost:8080")`,
	}}
	refined := review.Result{Behavior: review.BehaviorProfile{BehaviorChains: []string{
		".scan-cache.json:1 | 下载=1, 落地=0, 执行=0, 外联=9, 持久化=0, 提权=0, 凭据访问=1, 防御规避=0, 横向移动=0, 收集打包=0, C2信标=1",
	}}}
	structured := buildStructuredFindings(findings, refined, nil, "/tmp/demo", files)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	item := structured[0]
	if item.Category != "授权与许可证校验" {
		t.Fatalf("expected license category, got %+v", item)
	}
	if strings.Contains(item.AttackPath, ".scan-cache.json") || strings.Contains(item.AttackPath, "外联=9") {
		t.Fatalf("expected license attack path not to inherit outbound behavior chain, got %q", item.AttackPath)
	}
	capabilityLines := capabilityEvidenceForFinding(item, []review.CapabilityConsistency{{Capability: "外联/网络访问", Evidence: []string{`polymarket.py:6 requests.get(f"{GAMMA_API}/markets")`}, StaticDetected: true}}, []review.EvidenceInventory{{Category: "外联行为", Count: 1, Examples: []string{`polymarket.py:6 requests.get(f"{GAMMA_API}/markets")`}}}, refined.Behavior)
	if strings.Contains(strings.Join(capabilityLines, "\n"), "GAMMA_API") {
		t.Fatalf("expected license finding not to import outbound capability evidence, got %+v", capabilityLines)
	}
}
