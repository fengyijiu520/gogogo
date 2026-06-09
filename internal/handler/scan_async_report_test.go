package handler

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"skill-scanner/internal/llm"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

type fakeLLMReviewClient struct {
	mu            sync.Mutex
	results       map[string]*llm.AnalysisResult
	errors        map[string]error
	completions   []string
	obfuscation   map[string]*llm.ObfuscationAnalysisResult
	err           error
	calls         []string
	completeCalls []string
	delay         time.Duration
	inFlight      int
	maxConcurrent int
}

func (f *fakeLLMReviewClient) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completeCalls = append(f.completeCalls, systemPrompt+"|"+userPrompt)
	if f.err != nil {
		return "", f.err
	}
	idx := len(f.completeCalls) - 1
	if idx >= 0 && idx < len(f.completions) {
		return f.completions[idx], nil
	}
	return `{"verdict":"needs_manual_review","reason":"missing scripted completion"}`, nil
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
	callErr := f.errors[name]
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
	if callErr != nil {
		return nil, callErr
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

func TestCountFindingSeveritiesCountsByLocalizedLevel(t *testing.T) {
	findings := []plugins.Finding{{Severity: "高风险"}, {Severity: "中风险"}, {Severity: "低风险"}, {Severity: "待确认"}}
	high, medium, low := countFindingSeverities(findings)
	if high != 1 || medium != 1 || low != 2 {
		t.Fatalf("expected 1/1/2 severities, got %d/%d/%d", high, medium, low)
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
	for _, want := range []string{"命令执行", "代码证据 / scripts/run.py:20", "os.system(cmd)", "结构化建议: 移除 shell 执行并收敛命令来源"} {
		if !strings.Contains(section, want) {
			t.Fatalf("expected command-exec evidence preserved after refactor, missing %q in %q", want, section)
		}
	}
}
