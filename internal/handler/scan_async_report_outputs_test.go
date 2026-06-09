package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"skill-scanner/internal/docx"
	"skill-scanner/internal/logx"
	"skill-scanner/internal/review"
	reviewreport "skill-scanner/internal/review/report"
)

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

func TestBuildHTMLReportIncludesHTTPProbeOverviewSection(t *testing.T) {
	refined := review.Result{
		Behavior: review.BehaviorProfile{
			ProbeWarnings:      []string{"检测到下载与执行信号但未形成时序告警"},
			ScenarioExecutions: []review.ScenarioExecution{{Name: "python-main", Command: "python3 main.py", ExitCode: 0, HTTPPorts: []int{5000, 8080}, HTTPPaths: []string{"/health", "/status"}, HTTPMethod: "GET", HTTPPort: 5000, HTTPPath: "/health", HTTPStatusCode: 200, Output: []string{"http_probe method=GET port=5000 path=/health status=200"}}, {Name: "python-app-http-probe", Command: "python3 app.py", ExitCode: 0, HTTPPorts: []int{9000}, HTTPPaths: []string{"/admin"}, HTTPMethod: "POST", HTTPPort: 9000, HTTPPath: "/admin", HTTPStatusCode: 401, Output: []string{"http_probe method=POST port=9000 path=/admin status=401"}}, {Name: "python-api-http-probe", Command: "python3 api.py", ExitCode: 0, HTTPPorts: []int{9100}, HTTPPaths: []string{"/submit"}, HTTPMethod: "GET", HTTPPort: 9100, HTTPPath: "/submit", HTTPStatusCode: 405, Output: []string{"http_probe method=GET port=9100 path=/submit status=405"}}, {Name: "python-timeout-http-probe", Command: "python3 timeout.py", ExitCode: 124, HTTPPorts: []int{9200}, HTTPPaths: []string{"/healthz"}, Output: []string{"request timed out"}}, {Name: "python-module-http-probe", Command: "python3 module.py", ExitCode: 125, HTTPPorts: []int{9210}, HTTPPaths: []string{"/healthz"}, Output: []string{"No module named flask"}}, {Name: "python-bind-http-probe", Command: "python3 bind.py", ExitCode: 125, HTTPPorts: []int{9220}, HTTPPaths: []string{"/readyz"}, Output: []string{"bind failed on port 9220"}}, {Name: "python-crash-http-probe", Command: "python3 crash.py", ExitCode: 125, HTTPPorts: []int{9300}, HTTPPaths: []string{"/ready"}, Output: []string{"Traceback: startup error"}}, {Name: "python-exit-http-probe", Command: "python3 exit.py", ExitCode: 2, HTTPPorts: []int{9400}, HTTPPaths: []string{"/live"}, Output: []string{"usage error"}}, {Name: "python-refused-http-probe", Command: "python3 refused.py", ExitCode: 0, HTTPPorts: []int{9450}, HTTPPaths: []string{"/health"}, Output: []string{"http_probe_error error=<urlopen error [Errno 111] Connection refused>"}}, {Name: "python-unreachable-http-probe", Command: "python3 idle.py", ExitCode: 0, HTTPPorts: []int{9500}, HTTPPaths: []string{"/ping"}, Output: []string{"service started without listener"}}},
		},
		Pipeline: []review.PipelineStage{{Name: "sandbox_retry", Status: "completed"}},
	}
	htmlReport := buildHTMLReport("skill.zip", "", nil, baseScanOutput{}, refined, nil)
	for _, want := range []string{"业务风险看板", "HTTP 失败根因聚合", "验证结论摘要", "HTTP 探针概览", "HTTP 命中", "HTTP 未命中", "Top Failure", "3</span><p class=\"hint\" style=\"color:rgba(255,255,255,.78);margin:6px 0 0\">本次本地探针命中的入口数", "8</span><p class=\"hint\" style=\"color:rgba(255,255,255,.78);margin:6px 0 0\">候选入口仍未命中的数量", "<span class=\"pill\" style=\"font-size:14px;color:#fff;background:rgba(180,35,24,.32);border-color:rgba(255,255,255,.30)\">bind_failed=1</span>", "<span class=\"pill\" style=\"font-size:14px;color:#fff;background:rgba(33,86,209,.30);border-color:rgba(255,255,255,.30)\">connection_refused=1</span>", "<span class=\"pill\" style=\"font-size:14px;color:#fff;background:rgba(180,35,24,.32);border-color:rgba(255,255,255,.30)\">module_missing=1</span>", "候选端口与路径", "命中证据", "未命中原因", "修复动作", "可达入口", "需认证入口", "方法不匹配入口", "探针超时入口", "启动失败入口", "提前退出入口", "服务未起入口", "失败根因聚合", "失败根因标签", "probe_timeout=1", "module_missing=1", "runtime_exception=1", "process_early_exit=1", "connection_refused=1", "no_listener_detected=1", "reason=probe_timeout", "reason=module_missing", "reason=bind_failed", "reason=runtime_exception", "reason=process_early_exit", "reason=connection_refused", "reason=no_listener_detected", "ports=5000,8080", "paths=/health,/status", "port=5000", "path=/health", "status=401", "status=405", "python-timeout-http-probe", "python-module-http-probe", "python-bind-http-probe", "python-crash-http-probe", "python-exit-http-probe", "python-refused-http-probe", "python-unreachable-http-probe"} {
		if !strings.Contains(htmlReport, want) {
			t.Fatalf("expected html report contains %q, got %s", want, htmlReport)
		}
	}
}

func TestBuildReportsFromRealisticFixturePreserveDiagnostics(t *testing.T) {
	dir := createRealisticSkillFixtureTree(t)
	files, deps, cacheStats := collectBaseScanArtifacts(dir, nil)
	base := baseScanOutput{
		totalRules:      3,
		evaluatedRules:  3,
		profile:         buildSkillAnalysisProfile(dir, files, deps, []string{"network"}),
		sourceRoot:      dir,
		sourceFiles:     files,
		cacheStats:      cacheStats,
		ruleCoverage:    buildRuleCoverageSummary(nil, nil),
		coverageNote:    "fixture coverage",
		detectionErrors: nil,
	}
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:                  "SF-FIXTURE",
			RuleID:              "V7-009",
			Title:               "命令执行",
			Severity:            "中风险",
			Category:            "命令执行",
			SecurityVerdict:     "review",
			CodeEvidenceRefs:    []string{"scripts/run.py:2 subprocess.run(['python', '--version'])"},
			ContextEvidenceRefs: []string{"SKILL.md:2 用于审查代码安全风险，并按需读取仓库文件。"},
		}},
	}
	htmlReport := buildHTMLReport("realistic-fixture.zip", "", nil, base, refined, nil)
	payload := buildJSONReportPayload(htmlReport, "text", nil, base, refined)
	for _, want := range []string{"realistic-fixture.zip", "增量缓存", "评估完整性证明", "scripts/run.py"} {
		if !strings.Contains(htmlReport, want) {
			t.Fatalf("expected realistic fixture html contains %q", want)
		}
	}
	primary, ok := payload["primary_report"].(map[string]interface{})
	if !ok || primary["html"] == "" || payload["coverage"] == nil || payload["result"] == nil {
		t.Fatalf("expected realistic fixture json payload contains report sections, got %#v", payload)
	}
}

func TestRenderHTTPProbeOverviewSectionShowsResponseDigests(t *testing.T) {
	summary := map[string]interface{}{
		"http_probe_response_digests": []string{"python-main | method=GET | port=5000 | path=/health | status=200 | body_sha256=abc123def456 | body_sample={\"ok\":true}"},
	}

	htmlReport := renderHTTPProbeOverviewSection(summary)
	for _, want := range []string{"命中证据", "body_sha256=abc123def456", "body_sample={&#34;ok&#34;:true}"} {
		if !strings.Contains(htmlReport, want) {
			t.Fatalf("expected http probe response digest %q in %s", want, htmlReport)
		}
	}
}

func TestRenderHTTPProbeOverviewSectionShowsThreeColumnDiagnostics(t *testing.T) {
	summary := map[string]interface{}{
		"http_probe_candidates":            []string{"python-api-http-probe port=8080 paths=/health"},
		"http_probe_results":               []string{"python-api-http-probe GET 8080/health status=200"},
		"http_probe_response_digests":      []string{"python-api-http-probe body_sha256=abc123 body_sample=ok"},
		"http_probe_misses":                []string{"python-api-http-probe port=8080 path=/submit"},
		"http_probe_failure_reason_counts": []string{"connection_refused=1"},
		"http_probe_repair_actions":        []string{"connection_refused: 确认服务绑定到探针端口"},
	}

	htmlReport := renderHTTPProbeOverviewSection(summary)
	for _, want := range []string{"命中证据", "未命中原因", "修复动作", "body_sha256=abc123", "connection_refused=1"} {
		if !strings.Contains(htmlReport, want) {
			t.Fatalf("expected html contains %q, got %s", want, htmlReport)
		}
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
	base := baseScanOutput{
		taskID:    "task-mixed-001",
		requestID: "rid-mixed-001",
		trace:     []analysisTraceEvent{{Stage: "queued", Status: "completed", Message: "mixed polymarket scenario"}},
	}
	payload := buildJSONReportPayload("<html></html>", "text", nil, base, refined)
	items, ok := payload["obfuscation_evidence"].([]review.ObfuscationEvidence)
	if !ok {
		t.Fatalf("expected obfuscation_evidence in payload, got %#v", payload["obfuscation_evidence"])
	}
	if len(items) != 1 || items[0].Path != "payload.js" {
		t.Fatalf("unexpected obfuscation evidence payload: %+v", items)
	}
}

func TestBuildHTMLAndJSONReportIncludeRemediationVerification(t *testing.T) {
	refined := review.Result{
		Summary: review.ScoreSummary{Admission: "UserDecisionRequired", RiskLevel: "medium"},
		RemediationVerification: review.RemediationVerificationResult{
			ResolvedFindingIDs:   []string{"old-resolved"},
			OpenFindingIDs:       []string{"old-open"},
			RegressedFindingIDs:  []string{"old-regressed"},
			NewRelatedFindingIDs: []string{"new-related"},
			VerificationNotes: map[string]string{
				"old-resolved":  "风险代码已移除。",
				"old-open":      "风险仍存在。",
				"old-regressed": "风险回归。",
				"new-related":   "发现相关新增风险。",
			},
		},
	}

	htmlReport := buildHTMLReport("skill.zip", "", nil, baseScanOutput{}, refined, nil)
	for _, want := range []string{"修复验证", "old-resolved", "old-open", "old-regressed", "new-related", "风险代码已移除"} {
		if !strings.Contains(htmlReport, want) {
			t.Fatalf("expected html report contains %q, got %s", want, htmlReport)
		}
	}

	payload := buildJSONReportPayload(htmlReport, "text", nil, baseScanOutput{}, refined)
	if payload["remediation_verification"] == nil {
		t.Fatalf("expected json remediation verification payload, got %+v", payload)
	}
}

func TestBuildHTMLReportUsesNormalizedRiskCountsInHeroAndDashboard(t *testing.T) {
	refined := review.Result{
		Summary: review.ScoreSummary{Admission: "UserDecisionRequired", RiskLevel: "high", HighRisk: 3, MediumRisk: 0, LowRisk: 0},
		StructuredFindings: []review.StructuredFinding{
			{
				ID:         "SF-001",
				RuleID:     "V7-020",
				Title:      "许可证本地默认服务需复核",
				Severity:   "高风险",
				Category:   "授权与许可证校验",
				Confidence: "高",
				Evidence:   []string{"scripts/polymarket.py:12 LICENSE_SERVER=http://localhost:8080"},
			},
			{
				ID:         "SF-002",
				RuleID:     "V7-021",
				Title:      "仪表板未鉴权暴露",
				Severity:   "高风险",
				Category:   "暴露面与未鉴权服务",
				Confidence: "高",
				Evidence:   []string{"scripts/dashboard.py:20 app.run(host=\"127.0.0.1\", port=8080)"},
			},
			{
				ID:         "SF-003",
				RuleID:     "V7-003",
				Title:      "敏感数据外发与隐蔽通道",
				Severity:   "高风险",
				Category:   "外联与情报",
				Confidence: "高",
				Evidence:   []string{"scripts/polymarket.py:66 requests.post(telemetry_url, payload)"},
			},
		},
	}
	htmlReport := buildHTMLReport("skill.zip", "", nil, baseScanOutput{}, refined, nil)
	for _, want := range []string{
		"<strong>风险汇总</strong><span>0 / 1 / 2</span>",
		"<strong>高风险:</strong> 0（0.0%）",
		"<strong>中风险:</strong> 1（33.3%）",
		"<strong>低风险:</strong> 2（66.7%）",
	} {
		if !strings.Contains(htmlReport, want) {
			t.Fatalf("expected normalized risk count %q, got %s", want, htmlReport)
		}
	}
}

func TestBuildJSONReportPayloadUsesNormalizedRiskCountsInSummary(t *testing.T) {
	refined := review.Result{
		Summary: review.ScoreSummary{Admission: "UserDecisionRequired", RiskLevel: "high", HighRisk: 2, MediumRisk: 1, LowRisk: 0},
		StructuredFindings: []review.StructuredFinding{
			{
				ID:         "SF-001",
				RuleID:     "V7-020",
				Title:      "许可证本地默认服务需复核",
				Severity:   "高风险",
				Category:   "授权与许可证校验",
				Confidence: "高",
				Evidence:   []string{"scripts/polymarket.py:12 LICENSE_SERVER=http://localhost:8080"},
			},
			{
				ID:         "SF-002",
				RuleID:     "V7-030",
				Title:      "钱包私钥进入真实执行链",
				Severity:   "高风险",
				Category:   "凭据暴露",
				Confidence: "高",
				Evidence:   []string{"scripts/polymarket.py:88 wallet_private_key=os.getenv('WALLET_PRIVATE_KEY')"},
			},
			{
				ID:         "SF-003",
				RuleID:     "V7-021",
				Title:      "仪表板未鉴权暴露",
				Severity:   "高风险",
				Category:   "暴露面与未鉴权服务",
				Confidence: "高",
				Evidence:   []string{"scripts/dashboard.py:20 app.run(host=\"127.0.0.1\", port=8080)"},
			},
		},
	}
	payload := buildJSONReportPayload("<html></html>", "text", nil, baseScanOutput{}, refined)
	summary, ok := payload["summary_cn"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected summary_cn object, got %#v", payload["summary_cn"])
	}
	if summary["high_risk"] != 0 || summary["medium_risk"] != 1 || summary["low_risk"] != 2 {
		t.Fatalf("expected normalized risk counts in summary_cn, got %#v", summary)
	}
	rawCounts, ok := summary["raw_risk_counts"].(map[string]int)
	if !ok {
		t.Fatalf("expected raw_risk_counts in summary_cn, got %#v", summary["raw_risk_counts"])
	}
	if rawCounts["high"] != 2 || rawCounts["medium"] != 1 || rawCounts["low"] != 0 {
		t.Fatalf("unexpected raw risk counts in summary_cn: %#v", rawCounts)
	}
	normalizedCounts, ok := summary["normalized_risk_counts"].(map[string]int)
	if !ok {
		t.Fatalf("expected normalized_risk_counts in summary_cn, got %#v", summary["normalized_risk_counts"])
	}
	if normalizedCounts["high"] != 0 || normalizedCounts["medium"] != 1 || normalizedCounts["low"] != 2 {
		t.Fatalf("unexpected normalized risk counts object in summary_cn: %#v", normalizedCounts)
	}
}

func TestBuildHTMLAndJSONReportUseNormalizedRiskCountsInPolymarketLikeMixedScenario(t *testing.T) {
	refined := review.Result{
		Summary: review.ScoreSummary{Admission: "UserDecisionRequired", RiskLevel: "high", HighRisk: 4, MediumRisk: 0, LowRisk: 0},
		StructuredFindings: []review.StructuredFinding{
			{
				ID:         "SF-001",
				RuleID:     "V7-005",
				Title:      "许可证本地默认服务需复核",
				Severity:   "高风险",
				Category:   "授权与许可证校验",
				Confidence: "中",
				Evidence: []string{
					"scripts/polymarket.py:16 LICENSE_SERVER = os.getenv(\"LICENSE_SERVER\", \"http://localhost:8080\")",
					"scripts/polymarket.py:23 resp = requests.post(f\"{LICENSE_SERVER}/api/validate\")",
				},
			},
			{
				ID:         "SF-002",
				RuleID:     "V7-021",
				Title:      "仪表板未鉴权暴露",
				Severity:   "高风险",
				Category:   "暴露面与未鉴权服务",
				Confidence: "高",
				Evidence:   []string{"scripts/dashboard.py:88 app.run(host=\"127.0.0.1\", port=8080)"},
			},
			{
				ID:         "SF-003",
				RuleID:     "V7-004",
				Title:      "私钥明文存储风险",
				Severity:   "高风险",
				Category:   "凭据暴露",
				Confidence: "高",
				Evidence:   []string{"scripts/polymarket.py:188 requests.post(webhook, json={'private_key': wallet_private_key})"},
			},
			{
				ID:         "SF-004",
				RuleID:     "V7-022",
				Title:      "Python 系统包安装风险",
				Severity:   "高风险",
				Category:   "环境与构建风险",
				Confidence: "中",
				Evidence:   []string{"scripts/bootstrap.sh:12 pip3 install -r requirements.txt --break-system-packages"},
			},
		},
	}
	htmlReport := buildHTMLReport("polymarket-sniper-bot-standalone-1.0.1.zip", "", nil, baseScanOutput{}, refined, nil)
	for _, want := range []string{
		"<strong>风险汇总</strong><span>1 / 0 / 3</span>",
		"<strong>高风险:</strong> 1（25.0%）",
		"<strong>中风险:</strong> 0（0.0%）",
		"<strong>低风险:</strong> 3（75.0%）",
	} {
		if !strings.Contains(htmlReport, want) {
			t.Fatalf("expected mixed polymarket-like normalized count %q, got %s", want, htmlReport)
		}
	}
	payload := buildJSONReportPayload("<html></html>", "text", nil, baseScanOutput{}, refined)
	summary, ok := payload["summary_cn"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected summary_cn object, got %#v", payload["summary_cn"])
	}
	if summary["high_risk"] != 1 || summary["medium_risk"] != 0 || summary["low_risk"] != 3 {
		t.Fatalf("expected mixed normalized risk counts in summary_cn, got %#v", summary)
	}
	rawCounts, ok := summary["raw_risk_counts"].(map[string]int)
	if !ok {
		t.Fatalf("expected raw_risk_counts in mixed summary_cn, got %#v", summary["raw_risk_counts"])
	}
	if rawCounts["high"] != 4 || rawCounts["medium"] != 0 || rawCounts["low"] != 0 {
		t.Fatalf("unexpected mixed raw risk counts in summary_cn: %#v", rawCounts)
	}
	normalizedCounts, ok := summary["normalized_risk_counts"].(map[string]int)
	if !ok {
		t.Fatalf("expected normalized_risk_counts in mixed summary_cn, got %#v", summary["normalized_risk_counts"])
	}
	if normalizedCounts["high"] != 1 || normalizedCounts["medium"] != 0 || normalizedCounts["low"] != 3 {
		t.Fatalf("unexpected mixed normalized risk counts object in summary_cn: %#v", normalizedCounts)
	}
	riskCalibration, ok := payload["risk_calibration"].(reviewreport.RiskCalibrationSummary)
	if !ok {
		t.Fatalf("expected risk_calibration summary, got %#v", payload["risk_calibration"])
	}
	joinedBasis := strings.Join(riskCalibration.Basis, "\n")
	if !strings.Contains(joinedBasis, "高风险 1 项") || !strings.Contains(joinedBasis, "中风险 0 项") || !strings.Contains(joinedBasis, "低风险 3 项") {
		t.Fatalf("expected risk calibration basis uses normalized counts, got %#v", riskCalibration.Basis)
	}
}

func TestBuildJSONReportPayloadPolymarketMixedScenarioIncludesSecondaryFindingReviewMetadata(t *testing.T) {
	refined := review.Result{
		Summary: review.ScoreSummary{Admission: "UserDecisionRequired", RiskLevel: "high", HighRisk: 5, MediumRisk: 0, LowRisk: 0},
		StructuredFindings: []review.StructuredFinding{
			{
				ID:               "SF-001",
				RuleID:           "V7-005",
				Title:            "许可证本地默认服务需复核",
				Severity:         "高风险",
				Category:         "授权与许可证校验",
				Confidence:       "中",
				Evidence:         []string{"scripts/polymarket.py:16 LICENSE_SERVER = os.getenv(\"LICENSE_SERVER\", \"http://localhost:8080\")"},
				CalibrationBasis: []string{"本地 fallback 仅用于开发态，生成期已降为低风险。"},
				SecurityVerdict:  "review",
			},
			{
				ID:               "SF-002",
				RuleID:           "V7-021",
				Title:            "仪表板未鉴权暴露",
				Severity:         "高风险",
				Category:         "暴露面与未鉴权服务",
				Confidence:       "中",
				Evidence:         []string{"scripts/dashboard.py:88 app.run(host=\"127.0.0.1\", port=8080)"},
				CalibrationBasis: []string{"本地 loopback dashboard，生成期已降为低风险。"},
				SecurityVerdict:  "review",
			},
			{
				ID:               "SF-003",
				RuleID:           "V7-004",
				Title:            "私钥明文存储风险",
				Severity:         "高风险",
				Category:         "凭据暴露",
				Confidence:       "高",
				Evidence:         []string{"scripts/polymarket.py:188 requests.post(webhook, json={'private_key': wallet_private_key})"},
				CalibrationBasis: []string{"凭据进入真实外联执行链。"},
				SecurityVerdict:  "confirmed",
			},
			{
				ID:               "SF-004",
				RuleID:           "V7-022",
				Title:            "Python 系统包安装风险",
				Severity:         "高风险",
				Category:         "环境与构建风险",
				Confidence:       "中",
				Evidence:         []string{"scripts/bootstrap.sh:12 pip3 install -r requirements.txt --break-system-packages"},
				CalibrationBasis: []string{"宿主环境安装系统包，保留中风险。"},
				SecurityVerdict:  "review",
			},
			{
				ID:                  "SF-005",
				RuleID:              "V7-003",
				Title:               "敏感数据外发与隐蔽通道",
				Severity:            "高风险",
				Category:            "外联与情报",
				Confidence:          "待复核",
				Evidence:            []string{"examples/demo_agent.py:12 requests.post(webhook, json={'content': msg})"},
				CalibrationBasis:    []string{"当前证据主要位于文档、示例、测试或开发态上下文，优先按低优先级线索处理并保留人工复核。"},
				FalsePositiveChecks: []string{"确认该示例文件不会进入发布包或被动态加载。"},
				SecurityVerdict:     "review",
			},
		},
		FalsePositiveReviews: []review.FalsePositiveReview{{
			FindingID:          "SF-005",
			Verdict:            "待人工复核: 当前证据仍需确认是否进入真实发布链路。",
			EvidenceStrength:   "弱: 证据主要来自示例目录。",
			ReachabilityChecks: []string{"当前证据主要位于文档、示例或测试上下文，需优先确认该文件是否会进入发布包、运行镜像或动态加载链路。"},
			ExclusionChecks:    []string{"确认该示例文件不会进入发布包或被动态加载。"},
			RequiredFollowUp:   []string{"补充发布物清单或构建产物证明，确认文档、示例或测试内容不会进入真实运行链路。"},
		}},
	}
	base := baseScanOutput{
		taskID:    "task-mixed-001",
		requestID: "rid-mixed-001",
		trace:     []analysisTraceEvent{{Stage: "queued", Status: "completed", Message: "mixed polymarket scenario"}},
	}
	payload := buildJSONReportPayload("<html></html>", "text", nil, base, refined)
	summary, ok := payload["summary_cn"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected summary_cn object, got %#v", payload["summary_cn"])
	}
	if summary["high_risk"] != 1 || summary["medium_risk"] != 1 || summary["low_risk"] != 3 {
		t.Fatalf("expected normalized risk counts in mixed summary_cn, got %#v", summary)
	}
	result, ok := payload["result"].(review.Result)
	if !ok {
		t.Fatalf("expected review result retained in payload, got %#v", payload["result"])
	}
	if len(result.StructuredFindings) != 5 {
		t.Fatalf("expected structured findings retained in result payload, got %+v", result.StructuredFindings)
	}
	if result.StructuredFindings[4].ID != "SF-005" || result.StructuredFindings[4].SecurityVerdict != "review" {
		t.Fatalf("expected secondary documentation finding review verdict retained, got %+v", result.StructuredFindings[4])
	}
	if !slices.Contains(result.StructuredFindings[4].CalibrationBasis, "当前证据主要位于文档、示例、测试或开发态上下文，优先按低优先级线索处理并保留人工复核。") {
		t.Fatalf("expected calibration basis retained for secondary finding, got %+v", result.StructuredFindings[4].CalibrationBasis)
	}
	if len(result.FalsePositiveReviews) != 1 {
		t.Fatalf("expected false positive reviews retained in result payload, got %+v", result.FalsePositiveReviews)
	}
	if result.FalsePositiveReviews[0].FindingID != "SF-005" || !strings.Contains(result.FalsePositiveReviews[0].Verdict, "待人工复核") {
		t.Fatalf("expected false positive review metadata for secondary finding, got %+v", result.FalsePositiveReviews[0])
	}
	traceMetadata, ok := payload["trace_metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected trace_metadata object, got %#v", payload["trace_metadata"])
	}
	closureSummary, ok := summary["closure_summary"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected closure_summary in summary_cn, got %#v", summary["closure_summary"])
	}
	if narrative, ok := summary["closure_narrative"].(string); !ok || strings.TrimSpace(narrative) == "" {
		t.Fatalf("expected closure_narrative in summary_cn, got %#v", summary["closure_narrative"])
	}
	if _, ok := traceMetadata["closure_summary"].(map[string]interface{}); !ok {
		t.Fatalf("expected closure_summary in trace_metadata, got %#v", traceMetadata["closure_summary"])
	}
	if narrative, ok := traceMetadata["closure_narrative"].(string); !ok || strings.TrimSpace(narrative) == "" {
		t.Fatalf("expected closure_narrative in trace_metadata, got %#v", traceMetadata["closure_narrative"])
	}
	if topGaps, ok := closureSummary["top_gaps"].([]string); !ok || len(topGaps) == 0 {
		t.Fatalf("expected top_gaps in closure_summary, got %#v", closureSummary["top_gaps"])
	}
	if details, ok := closureSummary["top_gap_details"].([]string); !ok || len(details) == 0 || !strings.Contains(details[0], "缺口=") {
		t.Fatalf("expected top_gap_details in closure_summary, got %#v", closureSummary["top_gap_details"])
	}
	if got, ok := closureSummary["closure_rate"].(float64); !ok || got < 0 {
		t.Fatalf("expected closure_rate in closure_summary, got %#v", closureSummary["closure_rate"])
	}
	normalizedCounts, ok := traceMetadata["normalized_risk_counts"].(map[string]int)
	if !ok {
		t.Fatalf("expected normalized_risk_counts in trace_metadata, got %#v", traceMetadata["normalized_risk_counts"])
	}
	if normalizedCounts["high"] != 1 || normalizedCounts["medium"] != 1 || normalizedCounts["low"] != 3 {
		t.Fatalf("unexpected normalized risk counts in trace_metadata: %#v", normalizedCounts)
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
			Missing:       3,
			Stale:         1,
			ContentReused: 2,
			DerivedReused: 7,
			CacheEntries:  12,
			CacheVersion:  sourceArtifactCacheVersion,
			CacheFilePath: "/tmp/demo/.scan-cache.json",
			LoadWarning:   "缓存文件不存在，首次扫描将全量构建",
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
	if cachePart["missing_files"] != 3 || cachePart["stale_files"] != 1 || cachePart["cache_entries"] != 12 {
		t.Fatalf("unexpected incremental cache reason stats: %#v", cachePart)
	}
	if cachePart["content_reused"] != 2 {
		t.Fatalf("expected content reuse stats, got %#v", cachePart)
	}
	if cachePart["derived_reused"] != 7 {
		t.Fatalf("expected derived reuse stats, got %#v", cachePart)
	}
	if cachePart["cache_version"] != sourceArtifactCacheVersion || cachePart["load_warning"] == "" {
		t.Fatalf("expected cache diagnostics in coverage payload: %#v", cachePart)
	}
	if got, ok := cachePart["hit_rate"].(float64); !ok || got < 66.6 || got > 66.7 {
		t.Fatalf("expected hit_rate around 66.7, got %#v", cachePart["hit_rate"])
	}
	if got, ok := cachePart["reuse_rate"].(float64); !ok || got != 25 {
		t.Fatalf("expected reuse_rate 25.0, got %#v", cachePart["reuse_rate"])
	}
}

func TestBuildJSONReportPayloadIncludesRuleCoverageDiagnostics(t *testing.T) {
	base := baseScanOutput{ruleCoverage: ruleCoverageSummary{
		Version:          "test-v1",
		AutoTotal:        10,
		AutoCovered:      7,
		AutoUncovered:    []string{"R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"},
		ManualTotal:      2,
		ManualCandidates: []string{"M1", "M2", "M3"},
		Note:             "覆盖统计",
	}}
	payload := buildJSONReportPayload("<html></html>", "text", nil, base, review.Result{})
	coverage, ok := payload["coverage"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected coverage object, got %#v", payload["coverage"])
	}
	ruleCoverage, ok := coverage["rule_coverage"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected rule_coverage object, got %#v", coverage["rule_coverage"])
	}
	if got, ok := ruleCoverage["auto_coverage_rate"].(float64); !ok || got != 70 {
		t.Fatalf("expected auto coverage rate 70, got %#v", ruleCoverage["auto_coverage_rate"])
	}
	if samples, ok := ruleCoverage["auto_uncovered_samples"].([]string); !ok || len(samples) != 8 {
		t.Fatalf("expected limited uncovered samples, got %#v", ruleCoverage["auto_uncovered_samples"])
	}
	if candidates, ok := ruleCoverage["manual_candidates"].([]string); !ok || len(candidates) != 3 {
		t.Fatalf("expected manual candidates, got %#v", ruleCoverage["manual_candidates"])
	}
}

func TestRenderAppendixSectionIncrementalCacheHitRateBoundaries(t *testing.T) {
	baseZero := baseScanOutput{cacheStats: incrementalCacheStats{Enabled: true, Candidate: 0, Hit: 0, Miss: 0}}
	htmlZero := renderAppendixSection(baseZero, nil, reportIntegritySummary{})
	if !strings.Contains(htmlZero, "缓存命中率:</strong> 0.0%") {
		t.Fatalf("expected 0 candidate hit rate to be 0.0%%, got %q", htmlZero)
	}

	baseFull := baseScanOutput{cacheStats: incrementalCacheStats{Enabled: true, Candidate: 5, Hit: 5, Miss: 0}}
	htmlFull := renderAppendixSection(baseFull, nil, reportIntegritySummary{})
	if !strings.Contains(htmlFull, "缓存命中率:</strong> 100.0%") {
		t.Fatalf("expected full hit rate 100.0%%, got %q", htmlFull)
	}

	baseNone := baseScanOutput{cacheStats: incrementalCacheStats{Enabled: true, Candidate: 7, Hit: 0, Miss: 7}}
	htmlNone := renderAppendixSection(baseNone, nil, reportIntegritySummary{})
	if !strings.Contains(htmlNone, "缓存命中率:</strong> 0.0%") {
		t.Fatalf("expected no-hit rate 0.0%%, got %q", htmlNone)
	}
}

func TestRenderAppendixSectionShowsIncrementalCacheDiagnostics(t *testing.T) {
	base := baseScanOutput{cacheStats: incrementalCacheStats{
		Enabled:      true,
		Candidate:    12,
		Hit:          8,
		Miss:         4,
		Missing:      3,
		Stale:        1,
		ReadErrors:   2,
		CacheEntries: 10,
		CacheVersion: sourceArtifactCacheVersion,
		LoadWarning:  "缓存文件不存在，首次扫描将全量构建",
		SaveWarning:  "permission denied",
	}}
	html := renderAppendixSection(base, nil, reportIntegritySummary{})
	for _, want := range []string{"缺失", "失效", "读错误", "缓存条目", sourceArtifactCacheVersion, "缓存加载诊断", "缓存保存诊断"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected appendix contains cache diagnostic %q, got %s", want, html)
		}
	}
}

func TestRenderAppendixSectionShowsDisabledCacheReason(t *testing.T) {
	base := baseScanOutput{cacheStats: incrementalCacheStats{Enabled: false, DisabledReason: "SKILL_SCANNER_INCREMENTAL_SCAN_CACHE=false"}}
	html := renderAppendixSection(base, nil, reportIntegritySummary{})
	if !strings.Contains(html, "关闭原因") || !strings.Contains(html, "SKILL_SCANNER_INCREMENTAL_SCAN_CACHE=false") {
		t.Fatalf("expected disabled reason rendered, got %s", html)
	}
}

func TestRenderAppendixSectionShowsRuleCoverageDiagnostics(t *testing.T) {
	base := baseScanOutput{ruleCoverage: ruleCoverageSummary{
		AutoTotal:        4,
		AutoCovered:      3,
		AutoUncovered:    []string{"R1", "R2"},
		ManualCandidates: []string{"M1"},
		Note:             "覆盖说明",
	}}
	html := renderAppendixSection(base, nil, reportIntegritySummary{})
	for _, want := range []string{"可自动评估项覆盖: 3 / 4（75.0%）", "未覆盖自动项样例", "R1", "人工复核候选样例", "M1"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected appendix contains coverage diagnostic %q, got %s", want, html)
		}
	}
}

func TestRenderAppendixSectionShowsReportIntegritySummary(t *testing.T) {
	html := renderAppendixSection(baseScanOutput{}, nil, reportIntegritySummary{
		Status:      "passed_with_fixes",
		AutoFixes:   []string{"已净化增量缓存文件路径"},
		Issues:      []string{"仍有 1 条原始风险未映射到结构化 finding"},
		MappingGaps: []string{"规则=S2-P1-012；标题=SSRF-内网探测；位置=client.py:88"},
	})
	for _, want := range []string{"报告一致性预检", "状态:</strong> passed_with_fixes", "已净化增量缓存文件路径", "仍有 1 条原始风险未映射到结构化 finding", "未映射样例", "client.py:88"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected appendix contains %q, got %s", want, html)
		}
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

func TestBuildJSONReportPayloadIncludesSupplyChainSummary(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:                "SF-OSV-001",
			RuleID:            "V7-010-OSV",
			Title:             "依赖漏洞与供应链风险",
			Severity:          "高风险",
			Category:          "环境与构建风险",
			Confidence:        "高",
			AttackPath:        "已知漏洞依赖进入发布链路",
			Evidence:          []string{"OSV 证据: dependency=requests version=2.19.0 vuln=GHSA-test-1234"},
			CalibrationBasis:  []string{"OSV 命中高危依赖漏洞"},
			ReviewGuidance:    "升级依赖版本并复扫",
			Source:            "SecurityEngine",
			DeduplicatedCount: 1,
		}},
	}
	payload := buildJSONReportPayload("<html></html>", "text", nil, baseScanOutput{}, refined)
	summary, ok := payload["supply_chain_summary"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected supply_chain_summary object, got %#v", payload["supply_chain_summary"])
	}
	if summary["count"] != 1 {
		t.Fatalf("expected count=1, got %#v", summary["count"])
	}
	packages, ok := summary["packages"].([]string)
	if !ok || len(packages) != 1 || packages[0] != "requests" {
		t.Fatalf("expected requests package extracted, got %#v", summary["packages"])
	}
	vulns, ok := summary["vulnerability_ids"].([]string)
	if !ok || len(vulns) != 1 || vulns[0] != "GHSA-test-1234" {
		t.Fatalf("expected GHSA vuln extracted, got %#v", summary["vulnerability_ids"])
	}
}

func TestBuildJSONReportPayloadIncludesSandboxRetrySummary(t *testing.T) {
	refined := review.Result{
		Behavior: review.BehaviorProfile{
			ProbeWarnings:      []string{"检测到下载与执行信号但未形成时序告警"},
			ExecutionScenarios: []string{"scenario=python-main | command=python3 | reason=probe warning"},
			ScenarioExecutions: []review.ScenarioExecution{{Name: "python-main", Command: "python3 main.py", ExitCode: 0, HTTPPorts: []int{5000, 8080}, HTTPPaths: []string{"/health", "/status"}, HTTPMethod: "GET", HTTPPort: 5000, HTTPPath: "/health", HTTPStatusCode: 200, Output: []string{"http_probe method=GET port=5000 path=/health status=200", "ok"}, InputFiles: []string{"input.json"}}, {Name: "python-app-http-probe", Command: "python3 app.py", ExitCode: 0, HTTPPorts: []int{9000}, HTTPPaths: []string{"/admin"}, HTTPMethod: "POST", HTTPPort: 9000, HTTPPath: "/admin", HTTPStatusCode: 401, Output: []string{"http_probe method=POST port=9000 path=/admin status=401"}}, {Name: "python-api-http-probe", Command: "python3 api.py", ExitCode: 0, HTTPPorts: []int{9100}, HTTPPaths: []string{"/submit"}, HTTPMethod: "GET", HTTPPort: 9100, HTTPPath: "/submit", HTTPStatusCode: 405, Output: []string{"http_probe method=GET port=9100 path=/submit status=405"}}, {Name: "python-timeout-http-probe", Command: "python3 timeout.py", ExitCode: 124, HTTPPorts: []int{9200}, HTTPPaths: []string{"/healthz"}, Output: []string{"request timed out"}}, {Name: "python-module-http-probe", Command: "python3 module.py", ExitCode: 125, HTTPPorts: []int{9210}, HTTPPaths: []string{"/missing"}, Output: []string{"No module named flask"}}, {Name: "python-bind-http-probe", Command: "python3 bind.py", ExitCode: 125, HTTPPorts: []int{9220}, HTTPPaths: []string{"/readyz"}, Output: []string{"bind failed on port 9220"}}, {Name: "python-crash-http-probe", Command: "python3 crash.py", ExitCode: 125, HTTPPorts: []int{9300}, HTTPPaths: []string{"/ready"}, Output: []string{"Traceback: startup error"}}, {Name: "python-exit-http-probe", Command: "python3 exit.py", ExitCode: 2, HTTPPorts: []int{9400}, HTTPPaths: []string{"/live"}, Output: []string{"usage error"}}, {Name: "python-refused-http-probe", Command: "python3 refused.py", ExitCode: 0, HTTPPorts: []int{9450}, HTTPPaths: []string{"/health"}, Output: []string{"http_probe_error error=<urlopen error [Errno 111] Connection refused>"}}, {Name: "python-unreachable-http-probe", Command: "python3 idle.py", ExitCode: 0, HTTPPorts: []int{9500}, HTTPPaths: []string{"/ping"}, Output: []string{"service started without listener"}}},
			Differentials:      []review.DifferentialProbe{{Scenario: "vm-profile", Triggered: true, Summary: "VM 场景下出现额外执行信号"}},
		},
		Pipeline: []review.PipelineStage{{
			Name:   "sandbox_retry",
			Status: "completed",
			Input:  "检测到下载与执行信号但未形成时序告警",
			Output: "自动复测完成，新增 IoC 2 个，探针告警 1 条",
		}},
	}
	refined.Behavior.ScenarioExecutions = append(refined.Behavior.ScenarioExecutions, review.ScenarioExecution{Name: "python-budget-http-probe", Command: "python3 budget.py", ExitCode: 0, HTTPPorts: []int{9500}, HTTPPaths: []string{"/health"}, Output: []string{"http_probe_budget requests=80 max=80"}})
	refined.Behavior.ScenarioExecutions[0].Output[0] = "http_probe method=GET port=5000 path=/health status=200 body_sha256=abc123 body_sample=ok"
	payload := buildJSONReportPayload("<html></html>", "text", nil, baseScanOutput{}, refined)
	summary, ok := payload["sandbox_retry_summary"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected sandbox_retry_summary object, got %#v", payload["sandbox_retry_summary"])
	}
	if summary["status"] != "已完成" {
		t.Fatalf("expected localized retry status, got %#v", summary["status"])
	}
	if summary["result"] != "自动复测完成，新增 IoC 2 个，探针告警 1 条" {
		t.Fatalf("expected retry output retained, got %#v", summary["result"])
	}
	runtimeSummary, ok := summary["runtime_observation_summary"].([]string)
	if !ok || len(runtimeSummary) == 0 || !strings.Contains(strings.Join(runtimeSummary, " | "), "HTTP 候选") || !strings.Contains(strings.Join(runtimeSummary, " | "), "失败根因") {
		t.Fatalf("expected runtime observation summary retained, got %#v", summary["runtime_observation_summary"])
	}
	warnings, ok := summary["probe_warnings"].([]string)
	if !ok || len(warnings) != 1 || warnings[0] != "检测到下载与执行信号但未形成时序告警" {
		t.Fatalf("expected retry warnings retained, got %#v", summary["probe_warnings"])
	}
	diffs, ok := summary["triggered_differentials"].([]string)
	if !ok || len(diffs) != 1 || diffs[0] != "VM 场景下出现额外执行信号" {
		t.Fatalf("expected retry differentials retained, got %#v", summary["triggered_differentials"])
	}
	scenarios, ok := summary["execution_scenarios"].([]string)
	if !ok || len(scenarios) != 1 || scenarios[0] != "scenario=python-main | command=python3 | reason=probe warning" {
		t.Fatalf("expected retry scenarios retained, got %#v", summary["execution_scenarios"])
	}
	executions, ok := summary["scenario_executions"].([]string)
	if !ok || len(executions) != 8 || !strings.Contains(executions[0], "python-main") || !strings.Contains(executions[0], "exit=0") {
		t.Fatalf("expected scenario execution summary retained, got %#v", summary["scenario_executions"])
	}
	httpProbe, ok := summary["http_probe_results"].([]string)
	if !ok || len(httpProbe) != 3 || !strings.Contains(httpProbe[0], "port=5000") || !strings.Contains(httpProbe[0], "path=/health") || !strings.Contains(httpProbe[0], "status=200") {
		t.Fatalf("expected http probe results retained, got %#v", summary["http_probe_results"])
	}
	httpCandidates, ok := summary["http_probe_candidates"].([]string)
	if !ok || len(httpCandidates) != 8 || !strings.Contains(httpCandidates[0], "ports=5000,8080") || !strings.Contains(httpCandidates[0], "paths=/health,/status") {
		t.Fatalf("expected http probe candidates retained, got %#v", summary["http_probe_candidates"])
	}
	httpMisses, ok := summary["http_probe_misses"].([]string)
	if !ok || len(httpMisses) != 8 || !strings.Contains(httpMisses[0], "python-main") || !strings.Contains(httpMisses[0], "ports=8080") || !strings.Contains(httpMisses[0], "paths=/status") {
		t.Fatalf("expected http probe misses retained, got %#v", summary["http_probe_misses"])
	}
	httpFailureReasons, ok := summary["http_probe_failure_reasons"].([]string)
	if !ok || len(httpFailureReasons) != 8 || !strings.Contains(strings.Join(httpFailureReasons, " | "), "reason=probe_timeout") || !strings.Contains(strings.Join(httpFailureReasons, " | "), "reason=module_missing") || !strings.Contains(strings.Join(httpFailureReasons, " | "), "reason=bind_failed") || !strings.Contains(strings.Join(httpFailureReasons, " | "), "reason=runtime_exception") || !strings.Contains(strings.Join(httpFailureReasons, " | "), "reason=process_early_exit") || !strings.Contains(strings.Join(httpFailureReasons, " | "), "reason=connection_refused") || !strings.Contains(strings.Join(httpFailureReasons, " | "), "reason=no_listener_detected") || !strings.Contains(strings.Join(httpFailureReasons, " | "), "reason=probe_budget_exhausted") {
		t.Fatalf("expected http probe failure reasons retained, got %#v", summary["http_probe_failure_reasons"])
	}
	httpFailureReasonCounts, ok := summary["http_probe_failure_reason_counts"].([]string)
	if !ok || len(httpFailureReasonCounts) != 8 || !strings.Contains(strings.Join(httpFailureReasonCounts, " | "), "probe_timeout=1") || !strings.Contains(strings.Join(httpFailureReasonCounts, " | "), "module_missing=1") || !strings.Contains(strings.Join(httpFailureReasonCounts, " | "), "bind_failed=1") || !strings.Contains(strings.Join(httpFailureReasonCounts, " | "), "runtime_exception=1") || !strings.Contains(strings.Join(httpFailureReasonCounts, " | "), "process_early_exit=1") || !strings.Contains(strings.Join(httpFailureReasonCounts, " | "), "connection_refused=1") || !strings.Contains(strings.Join(httpFailureReasonCounts, " | "), "no_listener_detected=1") || !strings.Contains(strings.Join(httpFailureReasonCounts, " | "), "probe_budget_exhausted=1") {
		t.Fatalf("expected http probe failure reason counts retained, got %#v", summary["http_probe_failure_reason_counts"])
	}
	httpRepairActions, ok := summary["http_probe_repair_actions"].([]string)
	if !ok || len(httpRepairActions) != 8 || !strings.Contains(strings.Join(httpRepairActions, " | "), "probe_timeout: 延长启动等待时间") || !strings.Contains(strings.Join(httpRepairActions, " | "), "module_missing: 补齐运行依赖") || !strings.Contains(strings.Join(httpRepairActions, " | "), "bind_failed: 检查监听") || !strings.Contains(strings.Join(httpRepairActions, " | "), "runtime_exception: 收集启动 traceback") || !strings.Contains(strings.Join(httpRepairActions, " | "), "process_early_exit: 修正启动命令") || !strings.Contains(strings.Join(httpRepairActions, " | "), "connection_refused: 确认服务实际监听端口") || !strings.Contains(strings.Join(httpRepairActions, " | "), "no_listener_detected: 确认服务实际监听端口") || !strings.Contains(strings.Join(httpRepairActions, " | "), "probe_budget_exhausted: 收窄候选端口") {
		t.Fatalf("expected http probe repair actions retained, got %#v", summary["http_probe_repair_actions"])
	}
	httpSummary, ok := payload["http_probe_summary"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected http_probe_summary object, got %#v", payload["http_probe_summary"])
	}
	candidateTargets, ok := httpSummary["candidate_targets"].([]string)
	if !ok || len(candidateTargets) != 8 || !strings.Contains(candidateTargets[0], "ports=5000,8080") {
		t.Fatalf("expected http probe candidate targets retained, got %#v", httpSummary["candidate_targets"])
	}
	missedTargets, ok := httpSummary["missed_targets"].([]string)
	if !ok || len(missedTargets) != 8 || !strings.Contains(missedTargets[0], "paths=/status") {
		t.Fatalf("expected http probe missed targets retained, got %#v", httpSummary["missed_targets"])
	}
	matchedTargets, ok := httpSummary["matched_targets"].([]string)
	if !ok || len(matchedTargets) != 3 || !strings.Contains(matchedTargets[0], "path=/health") {
		t.Fatalf("expected http probe matched targets retained, got %#v", httpSummary["matched_targets"])
	}
	reachableTargets, ok := httpSummary["reachable_targets"].([]string)
	if !ok || len(reachableTargets) != 1 || !strings.Contains(reachableTargets[0], "status=200") {
		t.Fatalf("expected reachable targets retained, got %#v", httpSummary["reachable_targets"])
	}
	authTargets, ok := httpSummary["auth_required_targets"].([]string)
	if !ok || len(authTargets) != 1 || !strings.Contains(authTargets[0], "status=401") {
		t.Fatalf("expected auth required targets retained, got %#v", httpSummary["auth_required_targets"])
	}
	methodTargets, ok := httpSummary["method_mismatch_targets"].([]string)
	if !ok || len(methodTargets) != 1 || !strings.Contains(methodTargets[0], "status=405") {
		t.Fatalf("expected method mismatch targets retained, got %#v", httpSummary["method_mismatch_targets"])
	}
	timeoutTargets, ok := httpSummary["timeout_targets"].([]string)
	if !ok || len(timeoutTargets) != 1 || !strings.Contains(timeoutTargets[0], "python-timeout-http-probe") {
		t.Fatalf("expected timeout targets retained, got %#v", httpSummary["timeout_targets"])
	}
	startupTargets, ok := httpSummary["startup_failed_targets"].([]string)
	if !ok || len(startupTargets) != 3 || !strings.Contains(strings.Join(startupTargets, " | "), "python-module-http-probe") || !strings.Contains(strings.Join(startupTargets, " | "), "python-bind-http-probe") || !strings.Contains(strings.Join(startupTargets, " | "), "python-crash-http-probe") {
		t.Fatalf("expected startup failed targets retained, got %#v", httpSummary["startup_failed_targets"])
	}
	earlyExitTargets, ok := httpSummary["early_exit_targets"].([]string)
	if !ok || len(earlyExitTargets) != 1 || !strings.Contains(earlyExitTargets[0], "python-exit-http-probe") {
		t.Fatalf("expected early exit targets retained, got %#v", httpSummary["early_exit_targets"])
	}
	serviceUnreachableTargets, ok := httpSummary["service_unreachable_targets"].([]string)
	if !ok || len(serviceUnreachableTargets) != 3 || !strings.Contains(strings.Join(serviceUnreachableTargets, " | "), "python-refused-http-probe") || !strings.Contains(strings.Join(serviceUnreachableTargets, " | "), "python-unreachable-http-probe") || !strings.Contains(strings.Join(serviceUnreachableTargets, " | "), "python-budget-http-probe") {
		t.Fatalf("expected service unreachable targets retained, got %#v", httpSummary["service_unreachable_targets"])
	}
	failureReasons, ok := httpSummary["failure_reasons"].([]string)
	if !ok || len(failureReasons) != 8 || !strings.Contains(strings.Join(failureReasons, " | "), "reason=probe_timeout") || !strings.Contains(strings.Join(failureReasons, " | "), "reason=module_missing") || !strings.Contains(strings.Join(failureReasons, " | "), "reason=bind_failed") || !strings.Contains(strings.Join(failureReasons, " | "), "reason=runtime_exception") || !strings.Contains(strings.Join(failureReasons, " | "), "reason=process_early_exit") || !strings.Contains(strings.Join(failureReasons, " | "), "reason=connection_refused") || !strings.Contains(strings.Join(failureReasons, " | "), "reason=no_listener_detected") || !strings.Contains(strings.Join(failureReasons, " | "), "reason=probe_budget_exhausted") {
		t.Fatalf("expected failure reasons retained, got %#v", httpSummary["failure_reasons"])
	}
	failureReasonCounts, ok := httpSummary["failure_reason_counts"].([]string)
	if !ok || len(failureReasonCounts) != 8 || !strings.Contains(strings.Join(failureReasonCounts, " | "), "probe_timeout=1") || !strings.Contains(strings.Join(failureReasonCounts, " | "), "module_missing=1") || !strings.Contains(strings.Join(failureReasonCounts, " | "), "bind_failed=1") || !strings.Contains(strings.Join(failureReasonCounts, " | "), "runtime_exception=1") || !strings.Contains(strings.Join(failureReasonCounts, " | "), "process_early_exit=1") || !strings.Contains(strings.Join(failureReasonCounts, " | "), "connection_refused=1") || !strings.Contains(strings.Join(failureReasonCounts, " | "), "no_listener_detected=1") || !strings.Contains(strings.Join(failureReasonCounts, " | "), "probe_budget_exhausted=1") {
		t.Fatalf("expected failure reason counts retained, got %#v", httpSummary["failure_reason_counts"])
	}
	repairActions, ok := httpSummary["probe_repair_actions"].([]string)
	if !ok || len(repairActions) != 8 || !strings.Contains(strings.Join(repairActions, " | "), "probe_timeout: 延长启动等待时间") || !strings.Contains(strings.Join(repairActions, " | "), "module_missing: 补齐运行依赖") || !strings.Contains(strings.Join(repairActions, " | "), "bind_failed: 检查监听") || !strings.Contains(strings.Join(repairActions, " | "), "probe_budget_exhausted: 收窄候选端口") {
		t.Fatalf("expected probe repair actions retained, got %#v", httpSummary["probe_repair_actions"])
	}
	overview, ok := payload["http_probe_overview"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected http_probe_overview object, got %#v", payload["http_probe_overview"])
	}
	topFailureReasons, ok := overview["top_failure_reasons"].([]string)
	if !ok || len(topFailureReasons) != 5 || !strings.Contains(strings.Join(topFailureReasons, " | "), "bind_failed=1") || !strings.Contains(strings.Join(topFailureReasons, " | "), "connection_refused=1") || !strings.Contains(strings.Join(topFailureReasons, " | "), "module_missing=1") || !strings.Contains(strings.Join(topFailureReasons, " | "), "no_listener_detected=1") || !strings.Contains(strings.Join(topFailureReasons, " | "), "probe_budget_exhausted=1") {
		t.Fatalf("expected top failure reasons retained, got %#v", overview["top_failure_reasons"])
	}
	overviewRepairActions, ok := overview["probe_repair_actions"].([]string)
	if !ok || len(overviewRepairActions) != 8 || !strings.Contains(strings.Join(overviewRepairActions, " | "), "probe_timeout: 延长启动等待时间") || !strings.Contains(strings.Join(overviewRepairActions, " | "), "module_missing: 补齐运行依赖") || !strings.Contains(strings.Join(overviewRepairActions, " | "), "bind_failed: 检查监听") || !strings.Contains(strings.Join(overviewRepairActions, " | "), "probe_budget_exhausted: 收窄候选端口") {
		t.Fatalf("expected overview repair actions retained, got %#v", overview["probe_repair_actions"])
	}
	if overview["matched_target_count"] != 3 {
		t.Fatalf("expected matched_target_count=3, got %#v", overview["matched_target_count"])
	}
	if overview["missed_target_count"] != 8 {
		t.Fatalf("expected missed_target_count=8, got %#v", overview["missed_target_count"])
	}
	if evidenceColumn, ok := overview["evidence_column"].([]string); !ok || len(evidenceColumn) == 0 || !strings.Contains(strings.Join(evidenceColumn, " | "), "body_sha256=") {
		t.Fatalf("expected overview evidence column response digest, got %#v", overview["evidence_column"])
	}
	if missReasonColumn, ok := overview["miss_reason_column"].([]string); !ok || len(missReasonColumn) == 0 || !strings.Contains(strings.Join(missReasonColumn, " | "), "probe_timeout=1") {
		t.Fatalf("expected overview miss reason column, got %#v", overview["miss_reason_column"])
	}
	if repairActionColumn, ok := overview["repair_action_column"].([]string); !ok || len(repairActionColumn) == 0 || !strings.Contains(strings.Join(repairActionColumn, " | "), "module_missing: 补齐运行依赖") {
		t.Fatalf("expected overview repair action column, got %#v", overview["repair_action_column"])
	}
}

func TestClassifyHTTPProbeMissDetectsProcessExitBeforeProbeCompleted(t *testing.T) {
	failureType, failureReason := classifyHTTPProbeMiss(review.ScenarioExecution{
		Name:     "python-api-http-probe",
		ExitCode: 0,
		Output:   []string{"http_probe_error error=process exited before HTTP probe completed exit=2"},
	})
	if failureType != "early_exit" || failureReason != "process_early_exit" {
		t.Fatalf("expected process early exit classification, got type=%s reason=%s", failureType, failureReason)
	}
}

func TestBuildSandboxRetrySummaryIncludesHTTPPathMethods(t *testing.T) {
	refined := review.Result{
		Behavior: review.BehaviorProfile{
			ScenarioExecutions: []review.ScenarioExecution{{
				Name:            "python-api-http-probe",
				Command:         "python3 api.py",
				ExitCode:        0,
				HTTPPorts:       []int{8080},
				HTTPPaths:       []string{"/health", "/submit"},
				HTTPPathMethods: map[string][]string{"/health": {"GET"}, "/submit": {"POST"}},
				HTTPMethod:      "GET",
				HTTPPort:        8080,
				HTTPPath:        "/health",
				HTTPStatusCode:  200,
				Output:          []string{"http_probe method=GET port=8080 path=/health status=200"},
			}},
		},
		Pipeline: []review.PipelineStage{{Name: "sandbox_retry", Status: "completed"}},
	}
	summary := buildSandboxRetrySummary(refined)
	candidates, ok := summary["http_probe_candidates"].([]string)
	if !ok || len(candidates) != 1 || !strings.Contains(candidates[0], "path_methods=/health:GET,/submit:POST") {
		t.Fatalf("expected path method diagnostics in candidates, got %#v", summary["http_probe_candidates"])
	}
	misses, ok := summary["http_probe_misses"].([]string)
	if !ok || len(misses) != 1 || strings.Contains(misses[0], "/health:GET") || !strings.Contains(misses[0], "path_methods=/submit:POST") {
		t.Fatalf("expected path method diagnostics in misses, got %#v", summary["http_probe_misses"])
	}
	pathMethods, ok := summary["http_probe_path_methods"].([]string)
	if !ok || len(pathMethods) != 1 || !strings.Contains(pathMethods[0], "path_methods=/health:GET,/submit:POST") {
		t.Fatalf("expected path methods list, got %#v", summary["http_probe_path_methods"])
	}
	httpSummary := buildHTTPProbeSummary(summary)
	summaryPathMethods, ok := httpSummary["path_method_diagnostics"].([]string)
	if !ok || len(summaryPathMethods) != 1 || !strings.Contains(summaryPathMethods[0], "path_methods=/health:GET,/submit:POST") {
		t.Fatalf("expected http probe summary path methods, got %#v", httpSummary["path_method_diagnostics"])
	}
	payload := buildJSONReportPayload("<html></html>", "text", nil, baseScanOutput{}, refined)
	overview, ok := payload["http_probe_overview"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected http probe overview, got %#v", payload["http_probe_overview"])
	}
	diagnostics, ok := overview["candidate_diagnostics"].([]string)
	if !ok || len(diagnostics) == 0 || !strings.Contains(strings.Join(diagnostics, " | "), "path_methods=/health:GET,/submit:POST") {
		t.Fatalf("expected candidate diagnostics, got %#v", overview["candidate_diagnostics"])
	}
}

func TestBuildJSONReportPayloadIncludesTraceMetadata(t *testing.T) {
	base := baseScanOutput{
		taskID:    "task-trace-001",
		requestID: "rid-trace-001",
		trace: []analysisTraceEvent{
			{Stage: "queued", Status: "completed", Message: "扫描任务已入队并完成技能声明解析"},
			{Stage: "behavior_review", Status: "completed", Message: "沙箱行为、差分执行和威胁情报复核完成"},
		},
	}
	refined := review.Result{
		Summary: review.ScoreSummary{HighRisk: 3, MediumRisk: 1, LowRisk: 0},
		StructuredFindings: []review.StructuredFinding{
			{ID: "SF-001", RuleID: "V7-005", Title: "许可证本地默认服务需复核", Severity: "高风险", Category: "授权与许可证校验", Confidence: "中", Evidence: []string{"scripts/polymarket.py:16 LICENSE_SERVER = os.getenv(\"LICENSE_SERVER\", \"http://localhost:8080\")"}},
			{ID: "SF-002", RuleID: "V7-021", Title: "仪表板未鉴权暴露", Severity: "高风险", Category: "暴露面与未鉴权服务", Confidence: "高", Evidence: []string{"scripts/dashboard.py:88 app.run(host=\"127.0.0.1\", port=8080)"}},
			{ID: "SF-003", RuleID: "V7-004", Title: "私钥明文存储风险", Severity: "高风险", Category: "凭据暴露", Confidence: "高", Evidence: []string{"scripts/polymarket.py:188 requests.post(webhook, json={'private_key': wallet_private_key})"}},
		},
	}
	payload := buildJSONReportPayload("<html></html>", "text", nil, base, refined)
	summary, ok := payload["trace_metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected trace_metadata object, got %#v", payload["trace_metadata"])
	}
	if summary["task_id"] != "task-trace-001" || summary["request_id"] != "rid-trace-001" {
		t.Fatalf("expected trace identifiers preserved, got %#v", summary)
	}
	stages, ok := summary["trace_stages"].([]string)
	if !ok || len(stages) != 2 {
		t.Fatalf("expected trace stages retained, got %#v", summary["trace_stages"])
	}
	if stages[0] != "queued / 已完成 / 扫描任务已入队并完成技能声明解析" {
		t.Fatalf("unexpected first trace stage: %#v", stages)
	}
	rawCounts, ok := summary["raw_risk_counts"].(map[string]int)
	if !ok {
		t.Fatalf("expected raw_risk_counts in trace_metadata, got %#v", summary["raw_risk_counts"])
	}
	if rawCounts["high"] != 3 || rawCounts["medium"] != 1 || rawCounts["low"] != 0 {
		t.Fatalf("unexpected raw risk counts in trace_metadata: %#v", rawCounts)
	}
	normalizedCounts, ok := summary["normalized_risk_counts"].(map[string]int)
	if !ok {
		t.Fatalf("expected normalized_risk_counts in trace_metadata, got %#v", summary["normalized_risk_counts"])
	}
	if normalizedCounts["high"] != 1 || normalizedCounts["medium"] != 0 || normalizedCounts["low"] != 2 {
		t.Fatalf("unexpected normalized risk counts in trace_metadata: %#v", normalizedCounts)
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
	persistedID, _, err := persistReports(store, "perm-task", "admin", originalName, "", "", "", nil, base, refined)
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

func TestPersistReportsPreservesBaseRequestIDWithoutTaskRecord(t *testing.T) {
	store := newTestStore(t)
	originalName := "demo-skill.zip"
	scanPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(scanPath, "SKILL.md"), []byte("# Demo"), 0600); err != nil {
		t.Fatalf("write skill file: %v", err)
	}
	base := baseScanOutput{sourceRoot: scanPath, requestID: "rid-from-base"}
	refined := review.Result{}
	persistedID, _, err := persistReports(store, "missing-task", "admin", originalName, "", "", "", nil, base, refined)
	if err != nil {
		t.Fatalf("persist reports: %v", err)
	}
	report := store.GetReport(persistedID)
	if report == nil {
		t.Fatal("expected persisted report metadata")
	}
	if report.RequestID != "rid-from-base" {
		t.Fatalf("expected base request id preserved, got %q", report.RequestID)
	}
}

func TestPersistReportsStoresNormalizedRiskCountsForListings(t *testing.T) {
	store := newTestStore(t)
	originalName := "polymarket-sniper-bot-standalone-1.0.1.zip"
	scanPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(scanPath, "SKILL.md"), []byte("# Demo"), 0600); err != nil {
		t.Fatalf("write skill file: %v", err)
	}
	base := baseScanOutput{sourceRoot: scanPath}
	refined := review.Result{
		Summary: review.ScoreSummary{Admission: "UserDecisionRequired", RiskLevel: "high", HighRisk: 4, MediumRisk: 0, LowRisk: 0},
		StructuredFindings: []review.StructuredFinding{
			{
				ID:         "SF-001",
				RuleID:     "V7-005",
				Title:      "许可证本地默认服务需复核",
				Severity:   "高风险",
				Category:   "授权与许可证校验",
				Confidence: "中",
				Evidence:   []string{"scripts/polymarket.py:16 LICENSE_SERVER = os.getenv(\"LICENSE_SERVER\", \"http://localhost:8080\")"},
			},
			{
				ID:         "SF-002",
				RuleID:     "V7-021",
				Title:      "仪表板未鉴权暴露",
				Severity:   "高风险",
				Category:   "暴露面与未鉴权服务",
				Confidence: "高",
				Evidence:   []string{"scripts/dashboard.py:88 app.run(host=\"127.0.0.1\", port=8080)"},
			},
			{
				ID:         "SF-003",
				RuleID:     "V7-004",
				Title:      "私钥明文存储风险",
				Severity:   "高风险",
				Category:   "凭据暴露",
				Confidence: "高",
				Evidence:   []string{"scripts/polymarket.py:188 requests.post(webhook, json={'private_key': wallet_private_key})"},
			},
			{
				ID:         "SF-004",
				RuleID:     "V7-022",
				Title:      "Python 系统包安装风险",
				Severity:   "高风险",
				Category:   "环境与构建风险",
				Confidence: "中",
				Evidence:   []string{"scripts/bootstrap.sh:12 pip3 install -r requirements.txt --break-system-packages"},
			},
		},
	}
	persistedID, _, err := persistReports(store, "normalized-risk-task", "admin", originalName, "", "", "", nil, base, refined)
	if err != nil {
		t.Fatalf("persist reports: %v", err)
	}
	report := store.GetReport(persistedID)
	if report == nil {
		t.Fatal("expected persisted report metadata")
	}
	if report.HighRisk != 1 || report.MediumRisk != 0 || report.LowRisk != 3 {
		t.Fatalf("expected persisted normalized counts 1/0/3, got %d/%d/%d", report.HighRisk, report.MediumRisk, report.LowRisk)
	}
	if report.RiskLevel != "high" {
		t.Fatalf("expected persisted normalized risk level high, got %q", report.RiskLevel)
	}
	if report.Decision != "UserDecisionRequired" {
		t.Fatalf("expected persisted normalized decision UserDecisionRequired, got %q", report.Decision)
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

func TestBuildUploadedOriginalNameSummarizesMultipleFiles(t *testing.T) {
	files := []*multipart.FileHeader{{Filename: "skill.zip"}}
	if got := buildUploadedOriginalName(files); got != "skill.zip" {
		t.Fatalf("expected single file name preserved, got %q", got)
	}
	files = append(files, &multipart.FileHeader{Filename: "README.md"}, &multipart.FileHeader{Filename: "main.py"})
	if got := buildUploadedOriginalName(files); got != "skill.zip 等 3 个文件" {
		t.Fatalf("expected summarized multi-file name, got %q", got)
	}
}

func TestWritePersistedReportFilesWritesDocxHTMLAndJSON(t *testing.T) {
	dir := t.TempDir()
	files, err := writePersistedReportFiles(dir, "demo_report", "<html><body>Demo</body></html>", "Demo", nil, baseScanOutput{}, review.Result{})
	if err != nil {
		t.Fatalf("write persisted report files: %v", err)
	}
	for _, path := range []string{files.docxPath, files.htmlPath, files.jsonPath} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("expected artifact %s exists: %v", path, statErr)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("expected restricted permission for %s, got %#o", path, info.Mode().Perm())
		}
	}
	if files.pdfName != "demo_report.pdf" || !strings.HasSuffix(files.pdfPath, "demo_report.pdf") {
		t.Fatalf("expected pdf file naming prepared, got %+v", files)
	}
}

func TestPrepareUploadedScanRequestBuildsTaskAndWritesFiles(t *testing.T) {
	store := newTestStore(t)
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("files", "scripts/run.py")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write([]byte("print('ok')\n")); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := writer.WriteField("description", "demo skill"); err != nil {
		t.Fatalf("write description: %v", err)
	}
	if err := writer.WriteField("permissions", "network, command"); err != nil {
		t.Fatalf("write permissions: %v", err)
	}
	if err := writer.WriteField("selected_rule_ids", "V7-001,V7-003"); err != nil {
		t.Fatalf("write selected rules: %v", err)
	}
	if err := writer.WriteField("differential_enabled", "true"); err != nil {
		t.Fatalf("write differential enabled: %v", err)
	}
	if err := writer.WriteField("evasion_delay_threshold_secs", "9"); err != nil {
		t.Fatalf("write delay threshold: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	req := httptest.NewRequest("POST", "/scan", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req = req.WithContext(context.WithValue(req.Context(), logx.RequestIDContextKey, "rid-upload-test"))
	rec := httptest.NewRecorder()

	uploaded, handled := prepareUploadedScanRequest(store, rec, req)
	if handled {
		t.Fatalf("expected request preparation success, got status=%d body=%s", rec.Code, rec.Body.String())
	}
	if uploaded.taskID == "" || uploaded.taskDir == "" {
		t.Fatalf("expected task identifiers generated, got %+v", uploaded)
	}
	if uploaded.originalName != "run.py" {
		t.Fatalf("expected original file name, got %q", uploaded.originalName)
	}
	if uploaded.requestID != "rid-upload-test" {
		t.Fatalf("expected request id propagated, got %q", uploaded.requestID)
	}
	if uploaded.description != "demo skill" {
		t.Fatalf("expected description preserved, got %q", uploaded.description)
	}
	if len(uploaded.permissions) != 2 || uploaded.permissions[0] != "network" || uploaded.permissions[1] != "command" {
		t.Fatalf("expected parsed permissions, got %+v", uploaded.permissions)
	}
	if len(uploaded.selectedRuleIDs) != 2 || uploaded.selectedRuleIDs[0] != "V7-001" || uploaded.selectedRuleIDs[1] != "V7-003" {
		t.Fatalf("expected parsed selected rules, got %+v", uploaded.selectedRuleIDs)
	}
	if !uploaded.diffOptions.Enabled || uploaded.diffOptions.DelayThresholdSecs != 9 {
		t.Fatalf("expected parsed diff options, got %+v", uploaded.diffOptions)
	}
	data, err := os.ReadFile(filepath.Join(uploaded.taskDir, "run.py"))
	if err != nil {
		t.Fatalf("read uploaded file: %v", err)
	}
	if string(data) != "print('ok')\n" {
		t.Fatalf("expected uploaded content persisted, got %q", string(data))
	}
	if len(uploaded.files) != 1 {
		t.Fatalf("expected one uploaded file header, got %d", len(uploaded.files))
	}
}
