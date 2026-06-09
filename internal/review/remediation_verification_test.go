package review

import "testing"

func TestVerifyRemediationClassifiesResolvedOpenRegressedAndRelated(t *testing.T) {
	input := RemediationVerificationInput{
		PreviousFindings: []StructuredFinding{
			{ID: "old-resolved", RuleID: "V7-009", Title: "命令执行", Category: "命令执行", Evidence: []string{"scripts/run.py:10 os.system(cmd)"}, ReviewGuidance: "移除 shell 拼接"},
			{ID: "old-open", RuleID: "V7-004", Title: "凭据访问", Category: "凭据访问", Evidence: []string{"auth.py:8 open('/root/.netrc')"}, ReviewGuidance: "限制凭据读取"},
			{ID: "old-regressed", RuleID: "V7-003", Title: "外联", Category: "外联与情报", Evidence: []string{"net.py:5 requests.post(url)"}, ReviewGuidance: "限制外联目标"},
		},
		CurrentFindings: []StructuredFinding{
			{ID: "current-open", RuleID: "V7-004", Title: "凭据访问", Category: "凭据访问", Evidence: []string{"auth.py:9 open(configured_token_path)"}, ReviewGuidance: "限制凭据读取"},
			{ID: "current-regressed", RuleID: "V7-003", Title: "外联", Category: "外联与情报", Evidence: []string{"net.py:5 requests.post(url)"}, ReviewGuidance: "限制外联目标"},
			{ID: "current-related", RuleID: "V7-NEW", Title: "凭据打包", Category: "凭据访问", Evidence: []string{"collector.py:4 read token"}, ReviewGuidance: "限制凭据读取"},
		},
	}

	result := VerifyRemediation(input)
	assertContains(t, result.ResolvedFindingIDs, "old-resolved")
	assertContains(t, result.OpenFindingIDs, "old-open")
	assertContains(t, result.RegressedFindingIDs, "old-regressed")
	assertContains(t, result.NewRelatedFindingIDs, "current-related")
	for _, id := range []string{"old-resolved", "old-open", "old-regressed", "current-related"} {
		if result.VerificationNotes[id] == "" {
			t.Fatalf("expected verification note for %s, got %+v", id, result.VerificationNotes)
		}
	}
}

func assertContains(t *testing.T, items []string, want string) {
	t.Helper()
	for _, item := range items {
		if item == want {
			return
		}
	}
	t.Fatalf("expected %q in %+v", want, items)
}
