package combination

import (
	"crypto/sha1"
	"encoding/hex"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	admissionmodel "skill-scanner/internal/admission/model"
	admissionservice "skill-scanner/internal/admission/service"
	platformid "skill-scanner/internal/platform/id"
	tiadapter "skill-scanner/internal/review/ti"
)

type SkillOption struct {
	SkillID         string
	DisplayName     string
	Name            string
	Version         string
	AdmissionStatus string
	ReviewDecision  string
	RiskTags        []string
	UpdatedAt       int64
	ReportID        string
	Selected        bool
}

type Overview struct {
	Options         []SkillOption
	SelectedSkills  []SkillOption
	RunID           string
	SavedAt         int64
	CombinedProfile *admissionmodel.CapabilityProfile
	CombinedRisks   []CombinedRisk
	CombinedTags    []string
	Capabilities    []string
	InferredChains  []InferredChain
	Conclusion      Conclusion
}

type CombinedRisk struct {
	Risk         admissionmodel.ResidualRisk
	SourceSkills []RiskSourceSkill
}

type RiskSourceSkill struct {
	SkillID     string
	DisplayName string
}

type Conclusion struct {
	RiskLevel            string
	RiskLabel            string
	ClosureNarrative     string
	Recommendation       string
	RuleConfigWarning    string
	RuleConfigWarnLevel  string
	RuleConfigVersion    string
	RuleConfigRevision   string
	RuleContentHash      string
	RuleSourcePath       string
	SelectedSkillCount   int
	CapabilityCount      int
	HighRiskCount        int
	MediumRiskCount      int
	LowRiskCount         int
	SensitiveSignalCount int
	HighConfidenceChains int
	TransferRiskScore    float64
	TITargetCount        int
	TIThreatCount        int
	TISuspiciousCount    int
	TIAdjustmentScore    float64
	CacheReused          bool
}

type Service struct {
	admission *admissionservice.AdmissionService
	store     *Store
}

type SingleSkillBehaviorAnalysis struct {
	Capabilities   []string      `json:"capabilities"`
	CombinedTags   []string      `json:"combined_tags"`
	InferredChains []InferredChain `json:"inferred_chains"`
	SemanticChains []InferredChain `json:"semantic_chains,omitempty"`
	Conclusion     Conclusion    `json:"conclusion"`
}

type selectedSignal struct {
	Option  SkillOption
	Profile *admissionmodel.CapabilityProfile
}

type tiRiskSummary struct {
	TargetCount     int
	ThreatCount     int
	SuspiciousCount int
	Adjustment      float64
}

func NewService(admission *admissionservice.AdmissionService, store *Store) *Service {
	return &Service{admission: admission, store: store}
}

func AnalyzeSingleSkillBehavior(profile *admissionmodel.CapabilityProfile, risks []admissionmodel.ResidualRisk) SingleSkillBehaviorAnalysis {
	if profile == nil {
		profile = &admissionmodel.CapabilityProfile{}
	}
	profile.Normalize()
	option := SkillOption{SkillID: "single-skill", DisplayName: "当前技能"}
	signal := selectedSignal{Option: option, Profile: profile}
	selected := []SkillOption{option}
	selectedSignals := []selectedSignal{signal}
	combinedRisks := make([]CombinedRisk, 0, len(risks))
	combinedTags := make([]string, 0, len(risks))
	for _, risk := range risks {
		combinedRisks = append(combinedRisks, CombinedRisk{Risk: risk, SourceSkills: []RiskSourceSkill{{SkillID: option.SkillID, DisplayName: option.DisplayName}}})
		if tag := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(risk.Category), " ", "_")); tag != "" {
			combinedTags = append(combinedTags, tag)
		}
	}
	combinedTags = normalizeStrings(combinedTags)
	ruleChains := prioritizeInferredChains(inferChains(selectedSignals, profile))
	semanticChains := inferSemanticChains(selectedSignals, profile, ruleChains)
	chains := mergeAndSortChains(ruleChains, semanticChains)
	tiSummary := buildTIRiskSummary(selectedSignals)
	conclusion := buildConclusion(selected, profile, combinedRisks, chains, tiSummary)
	meta := getChainRulesMeta()
	conclusion.RuleConfigWarning = getChainRulesWarning()
	conclusion.RuleConfigWarnLevel = getChainRulesWarningLevel()
	conclusion.RuleConfigVersion = meta.Version
	conclusion.RuleConfigRevision = meta.Revision
	conclusion.RuleContentHash = meta.ContentHash
	conclusion.RuleSourcePath = meta.SourcePath
	return SingleSkillBehaviorAnalysis{
		Capabilities:   profile.ToDetectedCapabilities(),
		CombinedTags:   combinedTags,
		InferredChains: chains,
		SemanticChains: semanticChains,
		Conclusion:     conclusion,
	}
}

func (s *Service) BuildOverview(selectedSkillIDs []string, limit int) (*Overview, error) {
	if s == nil || s.admission == nil {
		return &Overview{CombinedProfile: &admissionmodel.CapabilityProfile{}}, nil
	}
	items, err := s.admission.ListSkills("", limit)
	if err != nil {
		return nil, err
	}
	selectedSet := make(map[string]bool, len(selectedSkillIDs))
	for _, skillID := range selectedSkillIDs {
		skillID = strings.TrimSpace(skillID)
		if skillID != "" {
			selectedSet[skillID] = true
		}
	}
	options := make([]SkillOption, 0, len(items))
	selected := make([]SkillOption, 0, len(selectedSet))
	selectedSignals := make([]selectedSignal, 0, len(selectedSet))
	combinedProfile := &admissionmodel.CapabilityProfile{}
	combinedRisks := make([]CombinedRisk, 0)
	combinedTags := make([]string, 0)
	riskIndex := map[string]int{}
	for _, item := range items {
		if item == nil {
			continue
		}
		option := SkillOption{
			SkillID:         item.SkillID,
			DisplayName:     defaultIfEmpty(item.DisplayName, item.Name),
			Name:            item.Name,
			Version:         defaultIfEmpty(item.Version, "-"),
			AdmissionStatus: string(item.AdmissionStatus),
			ReviewDecision:  string(item.ReviewDecision),
			RiskTags:        append([]string(nil), item.RiskTags...),
			UpdatedAt:       item.UpdatedAt,
			ReportID:        item.ReportID,
			Selected:        selectedSet[item.SkillID],
		}
		options = append(options, option)
		if !option.Selected {
			continue
		}
		selected = append(selected, option)
		detail, err := s.admission.GetSkillDetail(item.SkillID)
		if err != nil || detail == nil {
			continue
		}
		selectedSignals = append(selectedSignals, selectedSignal{Option: option, Profile: detail.Profile})
		mergeCapabilityProfile(combinedProfile, detail.Profile)
		combinedTags = append(combinedTags, item.RiskTags...)
		for _, risk := range detail.Risks {
			key := strings.TrimSpace(risk.ID + "|" + risk.Title)
			if key == "|" {
				continue
			}
			if idx, ok := riskIndex[key]; ok {
				combinedRisks[idx].SourceSkills = appendSourceSkill(combinedRisks[idx].SourceSkills, option)
				continue
			}
			riskIndex[key] = len(combinedRisks)
			combinedRisks = append(combinedRisks, CombinedRisk{
				Risk: risk,
				SourceSkills: []RiskSourceSkill{{
					SkillID:     option.SkillID,
					DisplayName: option.DisplayName,
				}},
			})
		}
	}
	combinedProfile.Normalize()
	fingerprint := selectionFingerprint(selectedSignals)
	if cached := s.tryReuseCachedOverview(selected, fingerprint); cached != nil {
		cached.Options = options
		cached.SelectedSkills = selected
		cached.Conclusion.CacheReused = true
		return cached, nil
	}
	combinedTags = normalizeStrings(combinedTags)
	ruleChains := prioritizeInferredChains(inferChains(selectedSignals, combinedProfile))
	semanticChains := inferSemanticChains(selectedSignals, combinedProfile, ruleChains)
	inferredChains := mergeAndSortChains(ruleChains, semanticChains)
	tiSummary := buildTIRiskSummary(selectedSignals)
	overview := &Overview{
		Options:         options,
		SelectedSkills:  selected,
		CombinedProfile: combinedProfile,
		CombinedRisks:   combinedRisks,
		CombinedTags:    combinedTags,
		Capabilities:    combinedProfile.ToDetectedCapabilities(),
		InferredChains:  inferredChains,
		Conclusion:      buildConclusion(selected, combinedProfile, combinedRisks, inferredChains, tiSummary),
	}
	overview.Conclusion.CacheReused = false
	meta := getChainRulesMeta()
	overview.Conclusion.RuleConfigWarning = getChainRulesWarning()
	overview.Conclusion.RuleConfigWarnLevel = getChainRulesWarningLevel()
	overview.Conclusion.RuleConfigVersion = meta.Version
	overview.Conclusion.RuleConfigRevision = meta.Revision
	overview.Conclusion.RuleContentHash = meta.ContentHash
	overview.Conclusion.RuleSourcePath = meta.SourcePath
	runID, savedAt, err := s.saveOverview(selected, overview, fingerprint)
	if err != nil {
		return nil, err
	}
	overview.RunID = runID
	overview.SavedAt = savedAt
	return overview, nil
}

func buildTIRiskSummary(selected []selectedSignal) tiRiskSummary {
	targets := extractNetworkTargetsFromSelected(selected)
	if len(targets) == 0 {
		return tiRiskSummary{}
	}
	adapter := tiadapter.NewAdapter()
	reputations, _, adjustment := adapter.Query(targets)
	summary := tiRiskSummary{TargetCount: len(reputations), Adjustment: adjustment}
	for _, rep := range reputations {
		repKind := strings.ToLower(strings.TrimSpace(rep.Reputation))
		if repKind == "malicious" || repKind == "high-risk" {
			summary.ThreatCount++
		}
		if repKind == "suspicious" || repKind == "policy" {
			summary.SuspiciousCount++
		}
	}
	return summary
}

func extractNetworkTargetsFromSelected(selected []selectedSignal) []string {
	urlPattern := regexp.MustCompile(`(?i)https?://[^\s"')]+`)
	domainPattern := regexp.MustCompile(`(?i)\b([a-z0-9-]+\.)+[a-z]{2,}\b`)
	ipv4Pattern := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	sha256Pattern := regexp.MustCompile(`(?i)\b[a-f0-9]{64}\b`)
	seen := map[string]bool{}
	out := make([]string, 0, 16)
	for _, item := range selected {
		if item.Profile == nil {
			continue
		}
		for _, evidence := range item.Profile.Evidence {
			for _, target := range urlPattern.FindAllString(evidence, -1) {
				if isExternalNetworkTarget(target) {
					out = appendUniqueTarget(out, seen, target)
				}
			}
			for _, target := range domainPattern.FindAllString(evidence, -1) {
				if isExternalNetworkTarget(target) {
					out = appendUniqueTarget(out, seen, target)
				}
			}
			for _, target := range ipv4Pattern.FindAllString(evidence, -1) {
				if isExternalNetworkTarget(target) {
					out = appendUniqueTarget(out, seen, target)
				}
			}
			for _, target := range sha256Pattern.FindAllString(evidence, -1) {
				out = appendUniqueTarget(out, seen, target)
			}
		}
	}
	return out
}

func isExternalNetworkTarget(raw string) bool {
	v := strings.TrimSpace(strings.ToLower(raw))
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		u, err := url.Parse(v)
		if err != nil {
			return false
		}
		host := strings.TrimSpace(strings.ToLower(u.Hostname()))
		return isExternalHost(host)
	}
	return isExternalHost(v)
}

func isExternalHost(host string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "" {
		return false
	}
	if h == "localhost" || h == "0.0.0.0" || h == "::1" {
		return false
	}
	if strings.HasSuffix(h, ".local") {
		return false
	}
	if ip := net.ParseIP(h); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return false
		}
		return true
	}
	if strings.HasPrefix(h, "127.") {
		return false
	}
	if !strings.Contains(h, ".") {
		return false
	}
	return true
}

func appendUniqueTarget(out []string, seen map[string]bool, target string) []string {
	target = strings.TrimSpace(target)
	if target == "" || seen[target] {
		return out
	}
	seen[target] = true
	return append(out, target)
}

func mergeCapabilityProfile(dst, src *admissionmodel.CapabilityProfile) {
	if dst == nil || src == nil {
		return
	}
	dst.NetworkAccess = dst.NetworkAccess || src.NetworkAccess
	dst.FileRead = dst.FileRead || src.FileRead
	dst.FileWrite = dst.FileWrite || src.FileWrite
	dst.CommandExec = dst.CommandExec || src.CommandExec
	dst.SensitiveDataAccess = dst.SensitiveDataAccess || src.SensitiveDataAccess
	dst.ExternalFetch = dst.ExternalFetch || src.ExternalFetch
	dst.DataCollection = dst.DataCollection || src.DataCollection
	dst.Persistence = dst.Persistence || src.Persistence
	dst.PrivilegeUse = dst.PrivilegeUse || src.PrivilegeUse
	dst.ToolInvocation = dst.ToolInvocation || src.ToolInvocation
	if dst.CapabilityLevels == nil {
		dst.CapabilityLevels = map[string]float64{}
	}
	if dst.CapabilityScopes == nil {
		dst.CapabilityScopes = map[string][]string{}
	}
	for k, v := range src.CapabilityLevels {
		if v > dst.CapabilityLevels[k] {
			dst.CapabilityLevels[k] = v
		}
	}
	for capability, scopes := range src.CapabilityScopes {
		dst.CapabilityScopes[capability] = normalizeStrings(append(dst.CapabilityScopes[capability], scopes...))
	}
	dst.Tags = append(dst.Tags, src.Tags...)
	dst.Evidence = append(dst.Evidence, src.Evidence...)
}

func normalizeStrings(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func defaultIfEmpty(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func appendSourceSkill(items []RiskSourceSkill, option SkillOption) []RiskSourceSkill {
	for _, item := range items {
		if item.SkillID == option.SkillID {
			return items
		}
	}
	return append(items, RiskSourceSkill{SkillID: option.SkillID, DisplayName: option.DisplayName})
}

func selectedToSources(selected []selectedSignal) []RiskSourceSkill {
	out := make([]RiskSourceSkill, 0, len(selected))
	for _, item := range selected {
		out = appendSourceSkill(out, item.Option)
	}
	return out
}

func collectChainEvidence(selected []selectedSignal, keywords []string, fallback []string) []string {
	collected := make([]string, 0, len(fallback)+4)
	for _, item := range selected {
		if item.Profile == nil {
			continue
		}
		for _, evidence := range item.Profile.Evidence {
			lower := strings.ToLower(strings.TrimSpace(evidence))
			for _, keyword := range keywords {
				if keyword != "" && strings.Contains(lower, keyword) {
					collected = append(collected, evidence)
					break
				}
			}
		}
	}
	collected = normalizeStrings(collected)
	if len(collected) != 0 {
		return collected
	}
	return append([]string(nil), fallback...)
}

func (s *Service) saveOverview(selected []SkillOption, overview *Overview, fingerprint string) (string, int64, error) {
	if s == nil || s.store == nil || overview == nil {
		return "", 0, nil
	}
	if len(selected) < 2 {
		return "", 0, nil
	}
	selectedIDs := make([]string, 0, len(selected))
	for _, item := range selected {
		selectedIDs = append(selectedIDs, item.SkillID)
	}
	selectionKey := buildSelectionKey(selectedIDs)
	now := time.Now().Unix()
	runID := selectionKey
	if existing, ok := s.store.GetBySelectionKey(selectionKey); ok && existing != nil {
		runID = existing.RunID
	}
	if runID == "" {
		generated, err := platformid.GenerateHexID(16)
		if err == nil {
			runID = generated
		}
	}
	if runID == "" {
		runID = selectionKey
	}
	err := s.store.Save(&RunRecord{
		RunID:          runID,
		SelectionKey:   selectionKey,
		SelectionFingerprint: strings.TrimSpace(fingerprint),
		SelectedSkills: append([]string(nil), selectedIDs...),
		Overview:       toRunOverview(overview),
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	return runID, now, err
}

func selectionFingerprint(selected []selectedSignal) string {
	parts := make([]string, 0, len(selected))
	for _, item := range selected {
		skillID := strings.TrimSpace(item.Option.SkillID)
		if skillID == "" {
			continue
		}
		evidenceHash := ""
		if item.Profile != nil {
			evidenceHash = strings.Join(normalizeStrings(item.Profile.Evidence), "|")
		}
		parts = append(parts, skillID+"::"+evidenceHash)
	}
	sort.Strings(parts)
	s := strings.Join(parts, "##")
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (s *Service) tryReuseCachedOverview(selected []SkillOption, fingerprint string) *Overview {
	if s == nil || s.store == nil || len(selected) < 2 || strings.TrimSpace(fingerprint) == "" {
		return nil
	}
	ids := make([]string, 0, len(selected))
	for _, item := range selected {
		ids = append(ids, item.SkillID)
	}
	key := buildSelectionKey(ids)
	run, ok := s.store.GetBySelectionKey(key)
	if !ok || run == nil {
		return nil
	}
	if strings.TrimSpace(run.SelectionFingerprint) == "" || strings.TrimSpace(run.SelectionFingerprint) != strings.TrimSpace(fingerprint) {
		return nil
	}
	combinedProfile := run.Overview.CombinedProfile
	if combinedProfile == nil {
		combinedProfile = &admissionmodel.CapabilityProfile{}
	}
	inferredChains := make([]InferredChain, 0, len(run.Overview.InferredChains))
	for _, item := range run.Overview.InferredChains {
		inferredChains = append(inferredChains, InferredChain{
			ID: item.ID, Title: item.Title, Level: item.Level, Summary: item.Summary,
			Recommendation: item.Recommendation, ClosureRequirements: append([]string(nil), item.ClosureRequirements...), Evidence: append([]string(nil), item.Evidence...),
			AttackPath: append([]string(nil), item.AttackPath...), MITRETechniques: append([]string(nil), item.MITRETechniques...),
			SourceSkills: append([]RiskSourceSkill(nil), item.SourceSkills...),
		})
	}
	out := &Overview{
		RunID:           run.RunID,
		SavedAt:         run.UpdatedAt,
		CombinedProfile: combinedProfile,
		CombinedTags:    append([]string(nil), run.Overview.CombinedTags...),
		Capabilities:    append([]string(nil), run.Overview.Capabilities...),
		InferredChains:  inferredChains,
		Conclusion: Conclusion{
			RiskLevel:           run.Overview.RiskLevel,
			RiskLabel:           run.Overview.RiskLabel,
			ClosureNarrative:    run.Overview.ClosureNarrative,
			Recommendation:      run.Overview.Recommendation,
			RuleConfigWarning:   run.Overview.RuleConfigWarning,
			RuleConfigWarnLevel: run.Overview.RuleConfigWarnLevel,
			RuleConfigVersion:   run.Overview.RuleConfigVersion,
			RuleConfigRevision:  run.Overview.RuleConfigRevision,
			RuleContentHash:     run.Overview.RuleContentHash,
			RuleSourcePath:      run.Overview.RuleSourcePath,
			TITargetCount:       run.Overview.TITargetCount,
			TIThreatCount:       run.Overview.TIThreatCount,
			TISuspiciousCount:   run.Overview.TISuspiciousCount,
			TIAdjustmentScore:   run.Overview.TIAdjustmentScore,
		},
	}
	return out
}

func buildSelectionKey(skillIDs []string) string {
	items := normalizeStrings(skillIDs)
	sort.Strings(items)
	joined := strings.Join(items, ",")
	sum := sha1.Sum([]byte(joined))
	return hex.EncodeToString(sum[:])
}

func toRunOverview(overview *Overview) RunOverview {
	out := RunOverview{}
	if overview == nil {
		return out
	}
	out.RiskLevel = overview.Conclusion.RiskLevel
	out.RiskLabel = overview.Conclusion.RiskLabel
	out.ClosureNarrative = overview.Conclusion.ClosureNarrative
	out.Recommendation = overview.Conclusion.Recommendation
	out.CombinedProfile = overview.CombinedProfile
	out.RuleConfigWarning = overview.Conclusion.RuleConfigWarning
	out.RuleConfigWarnLevel = overview.Conclusion.RuleConfigWarnLevel
	out.RuleConfigVersion = overview.Conclusion.RuleConfigVersion
	out.RuleConfigRevision = overview.Conclusion.RuleConfigRevision
	out.RuleContentHash = overview.Conclusion.RuleContentHash
	out.RuleSourcePath = overview.Conclusion.RuleSourcePath
	out.TITargetCount = overview.Conclusion.TITargetCount
	out.TIThreatCount = overview.Conclusion.TIThreatCount
	out.TISuspiciousCount = overview.Conclusion.TISuspiciousCount
	out.TIAdjustmentScore = overview.Conclusion.TIAdjustmentScore
	out.Capabilities = append([]string(nil), overview.Capabilities...)
	out.CombinedTags = append([]string(nil), overview.CombinedTags...)
	out.CombinedRisks = make([]StoredRisk, 0, len(overview.CombinedRisks))
	for _, item := range overview.CombinedRisks {
		out.CombinedRisks = append(out.CombinedRisks, StoredRisk{
			ID:           item.Risk.ID,
			Title:        item.Risk.Title,
			Level:        item.Risk.Level,
			Category:     item.Risk.Category,
			Description:  item.Risk.Description,
			Mitigation:   item.Risk.Mitigation,
			SourceSkills: append([]RiskSourceSkill(nil), item.SourceSkills...),
		})
	}
	out.InferredChains = make([]StoredChain, 0, len(overview.InferredChains))
	for _, item := range overview.InferredChains {
		out.InferredChains = append(out.InferredChains, StoredChain{
			ID:              item.ID,
			Title:           item.Title,
			Level:           item.Level,
			Summary:         item.Summary,
			Recommendation:  item.Recommendation,
			ClosureRequirements: append([]string(nil), item.ClosureRequirements...),
			Evidence:        append([]string(nil), item.Evidence...),
			AttackPath:      append([]string(nil), item.AttackPath...),
			MITRETechniques: append([]string(nil), item.MITRETechniques...),
			SourceSkills:    append([]RiskSourceSkill(nil), item.SourceSkills...),
		})
	}
	out.SemanticChains = make([]StoredChain, 0, len(overview.InferredChains))
	for _, item := range overview.InferredChains {
		if !strings.HasPrefix(strings.TrimSpace(item.ID), "adaptive-") && !strings.HasPrefix(strings.TrimSpace(item.ID), "semantic-") {
			continue
		}
		out.SemanticChains = append(out.SemanticChains, StoredChain{
			ID:              item.ID,
			Title:           item.Title,
			Level:           item.Level,
			Summary:         item.Summary,
			Recommendation:  item.Recommendation,
			ClosureRequirements: append([]string(nil), item.ClosureRequirements...),
			Evidence:        append([]string(nil), item.Evidence...),
			AttackPath:      append([]string(nil), item.AttackPath...),
			MITRETechniques: append([]string(nil), item.MITRETechniques...),
			SourceSkills:    append([]RiskSourceSkill(nil), item.SourceSkills...),
		})
	}
	return out
}
