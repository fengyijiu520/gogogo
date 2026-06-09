package review

import "strings"

type EvaluationFixture struct {
	ID               string                      `json:"id"`
	Label            string                      `json:"label"`
	Findings         []StructuredFinding         `json:"findings,omitempty"`
	ExpectedFindings []ExpectedEvaluationFinding `json:"expected_findings,omitempty"`
	Notes            string                      `json:"notes,omitempty"`
}

type ExpectedEvaluationFinding struct {
	Category        string `json:"category"`
	Severity        string `json:"severity"`
	EvidencePattern string `json:"evidence_pattern"`
}

type EvaluationRunResult struct {
	PromptTemplateVersion string   `json:"prompt_template_version"`
	SchemaVersion         string   `json:"schema_version"`
	ModelConfigDigest     string   `json:"model_config_digest,omitempty"`
	PassRate              float64  `json:"pass_rate"`
	FalsePositiveCount    int      `json:"false_positive_count"`
	FalseNegativeCount    int      `json:"false_negative_count"`
	UnsupportedClaimCount int      `json:"unsupported_claim_count"`
	SchemaFailureCount    int      `json:"schema_failure_count"`
	FailedFixtures        []string `json:"failed_fixtures,omitempty"`
}

func RunEvaluationHarness(promptTemplateVersion, schemaVersion, modelConfigDigest string, fixtures []EvaluationFixture) EvaluationRunResult {
	result := EvaluationRunResult{PromptTemplateVersion: promptTemplateVersion, SchemaVersion: schemaVersion, ModelConfigDigest: modelConfigDigest}
	if len(fixtures) == 0 {
		result.PassRate = 1
		return result
	}
	passed := 0
	for _, fixture := range fixtures {
		fixturePassed, fp, fn, unsupported, schemaFailures := evaluateFixture(fixture)
		if fixturePassed {
			passed++
		} else {
			result.FailedFixtures = append(result.FailedFixtures, fixture.ID)
		}
		result.FalsePositiveCount += fp
		result.FalseNegativeCount += fn
		result.UnsupportedClaimCount += unsupported
		result.SchemaFailureCount += schemaFailures
	}
	result.PassRate = float64(passed) / float64(len(fixtures))
	return result
}

func evaluateFixture(fixture EvaluationFixture) (bool, int, int, int, int) {
	label := strings.ToLower(strings.TrimSpace(fixture.Label))
	confirmed := confirmedEvaluationFindings(fixture.Findings)
	schemaFailures := countSchemaFailures(fixture.Findings)
	unsupported := countUnsupportedEvaluationClaims(fixture.Findings)
	falsePositive := 0
	falseNegative := 0
	passed := schemaFailures == 0 && unsupported == 0
	if label == "benign" && len(confirmed) > 0 {
		falsePositive = len(confirmed)
		passed = false
	}
	for _, expected := range fixture.ExpectedFindings {
		if !matchesExpectedEvaluationFinding(expected, confirmed) {
			falseNegative++
			passed = false
		}
	}
	return passed, falsePositive, falseNegative, unsupported, schemaFailures
}

func confirmedEvaluationFindings(findings []StructuredFinding) []StructuredFinding {
	out := make([]StructuredFinding, 0, len(findings))
	for _, finding := range findings {
		if strings.EqualFold(strings.TrimSpace(finding.Confidence), "dismissed") || strings.EqualFold(strings.TrimSpace(finding.Source), "dismissed") {
			continue
		}
		if strings.Contains(strings.ToLower(finding.Confidence), "低") {
			continue
		}
		if len(finding.Evidence) > 0 {
			out = append(out, finding)
		}
	}
	return out
}

func matchesExpectedEvaluationFinding(expected ExpectedEvaluationFinding, findings []StructuredFinding) bool {
	for _, finding := range findings {
		if !evaluationTextMatches(expected.Category, finding.Category) {
			continue
		}
		if !evaluationTextMatches(expected.Severity, finding.Severity) {
			continue
		}
		if expected.EvidencePattern == "" || findingEvidenceContains(finding, expected.EvidencePattern) {
			return true
		}
	}
	return false
}

func countSchemaFailures(findings []StructuredFinding) int {
	count := 0
	for _, finding := range findings {
		if strings.TrimSpace(finding.ID) == "" || strings.TrimSpace(finding.Title) == "" || strings.TrimSpace(finding.Category) == "" || strings.TrimSpace(finding.Severity) == "" {
			count++
		}
	}
	return count
}

func countUnsupportedEvaluationClaims(findings []StructuredFinding) int {
	count := 0
	for _, finding := range findings {
		if len(finding.Evidence) == 0 && strings.TrimSpace(finding.AttackPath+finding.ReviewGuidance) != "" {
			count++
		}
	}
	return count
}

func findingEvidenceContains(finding StructuredFinding, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	for _, evidence := range finding.Evidence {
		if strings.Contains(strings.ToLower(evidence), pattern) {
			return true
		}
	}
	return false
}

func evaluationTextMatches(expected, actual string) bool {
	expected = strings.ToLower(strings.TrimSpace(expected))
	actual = strings.ToLower(strings.TrimSpace(actual))
	return expected == "" || expected == actual || strings.Contains(actual, expected)
}
