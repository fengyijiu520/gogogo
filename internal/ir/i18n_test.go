package ir

import (
	"fmt"
	"testing"
)

func TestTranslatorZH(t *testing.T) {
	tr := NewTranslator(LangZH)

	fmt.Printf("=== 中文翻译测试 ===\n")
	fmt.Printf("标题: %s\n", tr.T("report.title"))
	fmt.Printf("高风险: %s\n", tr.T("risk.high"))
	fmt.Printf("污点分析: %s\n", tr.T("analysis.taint"))
	fmt.Printf("修复建议: %s\n", tr.T("fix.sanitize_input"))

	if tr.T("report.title") != "技能安全审查报告" {
		t.Errorf("unexpected title: %s", tr.T("report.title"))
	}
}

func TestTranslatorEN(t *testing.T) {
	tr := NewTranslator(LangEN)

	fmt.Printf("=== English Translation Test ===\n")
	fmt.Printf("Title: %s\n", tr.T("report.title"))
	fmt.Printf("High Risk: %s\n", tr.T("risk.high"))
	fmt.Printf("Taint Analysis: %s\n", tr.T("analysis.taint"))
	fmt.Printf("Fix: %s\n", tr.T("fix.sanitize_input"))

	if tr.T("report.title") != "Skill Security Audit Report" {
		t.Errorf("unexpected title: %s", tr.T("report.title"))
	}
}

func TestTranslatorJA(t *testing.T) {
	tr := NewTranslator(LangJA)

	fmt.Printf("=== 日本語翻訳テスト ===\n")
	fmt.Printf("タイトル: %s\n", tr.T("report.title"))
	fmt.Printf("高リスク: %s\n", tr.T("risk.high"))
	fmt.Printf("汚染分析: %s\n", tr.T("analysis.taint"))
	fmt.Printf("修正提案: %s\n", tr.T("fix.sanitize_input"))

	if tr.T("report.title") != "スキルセキュリティ監査レポート" {
		t.Errorf("unexpected title: %s", tr.T("report.title"))
	}
}

func TestTranslatorFallback(t *testing.T) {
	// 未知语言应 fallback 到中文
	tr := NewTranslator("fr")

	if tr.T("report.title") != "技能安全审查报告" {
		t.Errorf("should fallback to zh, got: %s", tr.T("report.title"))
	}
}

func TestTranslatorMissingKey(t *testing.T) {
	tr := NewTranslator(LangZH)

	// 不存在的 key 应返回 key 本身
	if tr.T("nonexistent.key") != "nonexistent.key" {
		t.Error("missing key should return key itself")
	}
}

func TestTranslatorFormat(t *testing.T) {
	tr := NewTranslator(LangZH)

	result := tr.Tf("taint.description", "secret", "requests.post")
	fmt.Printf("格式化: %s\n", result)

	if result != "污点数据从 secret 传播到 requests.post" {
		t.Errorf("unexpected format: %s", result)
	}
}

func TestI18nReportZH(t *testing.T) {
	report := NewI18nReport(LangZH)

	analysis := FullAnalysis{
		TaintFindings: []TaintFinding{
			{
				Severity:    "高风险",
				Description: "凭据泄露",
				Source:      &TaintTag{VarName: "secret", Category: "env_access"},
				Sink:        &TaintSinkPoint{Call: CallExpr{FuncName: "requests.post"}},
			},
		},
		ChainResults: []ChainVerificationResult{
			{
				Description: "凭据外发链",
				Verified:    true,
				Confidence:  "高",
			},
		},
		SimilarityMatches: []SimilarityMatch{
			{
				Severity:   "高风险",
				PatternName: "凭据外发模式",
				Similarity: 0.85,
			},
		},
	}

	output := report.FormatAnalysis(analysis)
	fmt.Printf("=== 中文报告 ===\n%s\n", output)
}

func TestI18nReportEN(t *testing.T) {
	report := NewI18nReport(LangEN)

	analysis := FullAnalysis{
		TaintFindings: []TaintFinding{
			{
				Severity:    "高风险",
				Description: "Credential leak",
				Source:      &TaintTag{VarName: "secret", Category: "env_access"},
				Sink:        &TaintSinkPoint{Call: CallExpr{FuncName: "requests.post"}},
			},
		},
	}

	output := report.FormatAnalysis(analysis)
	fmt.Printf("=== English Report ===\n%s\n", output)
}

func TestI18nReportJA(t *testing.T) {
	report := NewI18nReport(LangJA)

	analysis := FullAnalysis{
		TaintFindings: []TaintFinding{
			{
				Severity:    "高风险",
				Description: "資格情報漏洩",
				Source:      &TaintTag{VarName: "secret", Category: "env_access"},
				Sink:        &TaintSinkPoint{Call: CallExpr{FuncName: "requests.post"}},
			},
		},
	}

	output := report.FormatAnalysis(analysis)
	fmt.Printf("=== 日本語レポート ===\n%s\n", output)
}

func TestFixSuggestion(t *testing.T) {
	tests := []struct {
		lang     Language
		category string
		wantZH   string
	}{
		{LangZH, "command_exec", "对输入做校验和消毒"},
		{LangZH, "network_access", "使用白名单限制允许的值"},
		{LangZH, "env_access", "移除硬编码的凭据"},
		{LangEN, "command_exec", "Validate and sanitize inputs"},
		{LangJA, "command_exec", "入力の検証とサニタイズ"},
	}

	for _, tt := range tests {
		report := NewI18nReport(tt.lang)
		got := report.GetFixSuggestion(tt.category)
		if got != tt.wantZH {
			t.Errorf("lang=%s category=%s: got %q, want %q", tt.lang, tt.category, got, tt.wantZH)
		}
	}
}

func TestSupportedI18nLanguages(t *testing.T) {
	langs := SupportedI18nLanguages()
	fmt.Printf("支持的语言: ")
	for _, l := range langs {
		fmt.Printf("%s(%s) ", LanguageName(l), l)
	}
	fmt.Println()

	if len(langs) != 3 {
		t.Errorf("expected 3 languages, got %d", len(langs))
	}
}
