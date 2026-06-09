package handler

import (
	"testing"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func TestBuildStructuredFindingRaisesMinimumSeverityForPythonSystemPackageRisk(t *testing.T) {
	findings := []plugins.Finding{{
		PluginName:  "SecurityEngine",
		RuleID:      "LLM-DETECT",
		Severity:    "低风险",
		Title:       "Python 环境隔离被绕过",
		Description: "bootstrap.sh 使用 pip3 install --break-system-packages",
		Location:    "bootstrap.sh:12",
		CodeSnippet: `pip3 install -r requirements.txt --break-system-packages`,
	}}
	structured := buildStructuredFindings(findings, review.Result{}, nil, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	if structured[0].Title != "Python 系统包安装风险" {
		t.Fatalf("expected normalized python package risk title, got %+v", structured[0])
	}
	if structured[0].Severity != "低风险" {
		t.Fatalf("expected local bootstrap python package risk lowered to low severity, got %+v", structured[0])
	}
}

func TestBuildStructuredFindingKeepsPythonSystemPackageRiskAtMediumWithoutExtraSupplyChainSignals(t *testing.T) {
	findings := []plugins.Finding{{
		PluginName:  "SecurityEngine",
		RuleID:      "LLM-DETECT",
		Severity:    "高风险",
		Title:       "Python 环境隔离被绕过",
		Description: "entrypoint.sh 使用 pip3 install --break-system-packages 安装依赖",
		Location:    "entrypoint.sh:8",
		CodeSnippet: `pip3 install -r requirements.txt --break-system-packages`,
	}}
	structured := buildStructuredFindings(findings, review.Result{}, nil, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	if structured[0].Severity != "中风险" {
		t.Fatalf("expected python system package risk calibrated to medium by default, got %+v", structured[0])
	}
}

func TestBuildStructuredFindingRaisesPythonSystemPackageRiskToHighWithSupplyChainSignals(t *testing.T) {
	findings := []plugins.Finding{{
		PluginName:  "SecurityEngine",
		RuleID:      "LLM-DETECT",
		Severity:    "中风险",
		Title:       "Python 环境隔离被绕过",
		Description: "bootstrap.sh 通过远程脚本拉起并执行 pip3 install --break-system-packages，存在供应链风险",
		Location:    "bootstrap.sh:12",
		CodeSnippet: "curl https://example.com/bootstrap.sh | sh\npip3 install -r requirements.txt --break-system-packages",
	}}
	structured := buildStructuredFindings(findings, review.Result{}, nil, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	if structured[0].Severity != "高风险" {
		t.Fatalf("expected python system package risk raised to high with extra supply chain signals, got %+v", structured[0])
	}
}

func TestBuildStructuredFindingLowersPythonSystemPackageRiskInContainerBuildContext(t *testing.T) {
	findings := []plugins.Finding{{
		PluginName:  "SecurityEngine",
		RuleID:      "LLM-DETECT",
		Severity:    "高风险",
		Title:       "Python 环境隔离被绕过",
		Description: "Dockerfile 构建阶段使用 pip3 install --break-system-packages 安装依赖",
		Location:    "Dockerfile:12",
		CodeSnippet: "FROM python:3.12\nRUN pip3 install -r requirements.txt --break-system-packages\n# image build stage",
	}}
	structured := buildStructuredFindings(findings, review.Result{}, nil, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	if structured[0].Severity != "低风险" {
		t.Fatalf("expected container build python package risk lowered to low, got %+v", structured[0])
	}
}
