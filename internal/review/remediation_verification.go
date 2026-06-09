package review

import "strings"

type RemediationVerificationInput struct {
	PreviousScanID   string              `json:"previous_scan_id,omitempty"`
	CurrentScanID    string              `json:"current_scan_id,omitempty"`
	PreviousFindings []StructuredFinding `json:"previous_findings,omitempty"`
	CurrentFindings  []StructuredFinding `json:"current_findings,omitempty"`
}

type RemediationVerificationResult struct {
	ResolvedFindingIDs   []string          `json:"resolved_finding_ids,omitempty"`
	OpenFindingIDs       []string          `json:"open_finding_ids,omitempty"`
	RegressedFindingIDs  []string          `json:"regressed_finding_ids,omitempty"`
	NewRelatedFindingIDs []string          `json:"new_related_finding_ids,omitempty"`
	VerificationNotes    map[string]string `json:"verification_notes,omitempty"`
}

func VerifyRemediation(input RemediationVerificationInput) RemediationVerificationResult {
	result := RemediationVerificationResult{VerificationNotes: map[string]string{}}
	if len(input.PreviousFindings) == 0 {
		return result
	}
	usedCurrent := map[int]bool{}
	for _, previous := range input.PreviousFindings {
		matchIdx, match := bestRemediationMatch(previous, input.CurrentFindings, usedCurrent)
		if matchIdx >= 0 {
			usedCurrent[matchIdx] = true
		}
		prevID := findingID(previous)
		if matchIdx < 0 {
			result.ResolvedFindingIDs = append(result.ResolvedFindingIDs, prevID)
			result.VerificationNotes[prevID] = "未在当前扫描中找到相同位置、证据或同类风险，按已解决记录。"
			continue
		}
		if remediationRegression(previous, match) {
			result.RegressedFindingIDs = append(result.RegressedFindingIDs, prevID)
			result.VerificationNotes[prevID] = "当前扫描再次出现相同位置或相同证据的风险，按回归记录。"
			continue
		}
		result.OpenFindingIDs = append(result.OpenFindingIDs, prevID)
		result.VerificationNotes[prevID] = "当前扫描仍存在同类风险或相关证据，需要继续修复或补充验证。"
	}
	for idx, current := range input.CurrentFindings {
		if usedCurrent[idx] {
			continue
		}
		if relatedToAnyPrevious(current, input.PreviousFindings) {
			id := findingID(current)
			result.NewRelatedFindingIDs = append(result.NewRelatedFindingIDs, id)
			result.VerificationNotes[id] = "当前扫描发现与历史修复主题相关的新风险，可能是风险迁移到新路径。"
		}
	}
	return result
}

func bestRemediationMatch(previous StructuredFinding, current []StructuredFinding, used map[int]bool) (int, StructuredFinding) {
	bestIdx := -1
	bestScore := 0
	var best StructuredFinding
	for idx, item := range current {
		if used[idx] {
			continue
		}
		score := remediationMatchScore(previous, item)
		if score > bestScore {
			bestIdx = idx
			bestScore = score
			best = item
		}
	}
	if bestScore < 2 {
		return -1, StructuredFinding{}
	}
	return bestIdx, best
}

func remediationMatchScore(a, b StructuredFinding) int {
	score := 0
	if sameText(a.RuleID, b.RuleID) && strings.TrimSpace(a.RuleID) != "" {
		score++
	}
	if sameText(a.Category, b.Category) && strings.TrimSpace(a.Category) != "" {
		score++
	}
	if sameText(primaryEvidence(a), primaryEvidence(b)) && primaryEvidence(a) != "" {
		score += 2
	}
	if intersectsNormalized(a.Evidence, b.Evidence) {
		score += 2
	}
	if sameText(a.Title, b.Title) && strings.TrimSpace(a.Title) != "" {
		score++
	}
	if remediationTheme(a) != "" && sameText(remediationTheme(a), remediationTheme(b)) {
		score++
	}
	return score
}

func remediationRegression(previous, current StructuredFinding) bool {
	return primaryEvidence(previous) != "" && sameText(primaryEvidence(previous), primaryEvidence(current)) || intersectsNormalized(previous.Evidence, current.Evidence)
}

func relatedToAnyPrevious(current StructuredFinding, previous []StructuredFinding) bool {
	for _, item := range previous {
		if remediationMatchScore(item, current) >= 1 && sameText(item.Category, current.Category) {
			return true
		}
	}
	return false
}

func findingID(finding StructuredFinding) string {
	if strings.TrimSpace(finding.ID) != "" {
		return strings.TrimSpace(finding.ID)
	}
	if strings.TrimSpace(finding.RuleID) != "" {
		return strings.TrimSpace(finding.RuleID)
	}
	return strings.TrimSpace(finding.Title)
}

func primaryEvidence(finding StructuredFinding) string {
	for _, item := range finding.Evidence {
		if strings.TrimSpace(item) != "" {
			return normalizeRemediationText(item)
		}
	}
	return ""
}

func remediationTheme(finding StructuredFinding) string {
	if strings.TrimSpace(finding.ReviewGuidance) != "" {
		return normalizeRemediationText(finding.ReviewGuidance)
	}
	return normalizeRemediationText(finding.Category + " " + finding.RuleID)
}

func sameText(a, b string) bool {
	return normalizeRemediationText(a) == normalizeRemediationText(b)
}

func intersectsNormalized(a, b []string) bool {
	seen := map[string]bool{}
	for _, item := range a {
		key := normalizeRemediationText(item)
		if key != "" {
			seen[key] = true
		}
	}
	for _, item := range b {
		if seen[normalizeRemediationText(item)] {
			return true
		}
	}
	return false
}

func normalizeRemediationText(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}
