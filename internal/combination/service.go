package combination

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"time"

	admissionmodel "skill-scanner/internal/admission/model"
	admissionservice "skill-scanner/internal/admission/service"
	platformid "skill-scanner/internal/platform/id"
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
	Recommendation       string
	SelectedSkillCount   int
	CapabilityCount      int
	HighRiskCount        int
	MediumRiskCount      int
	LowRiskCount         int
	SensitiveSignalCount int
	HighConfidenceChains int
}

type Service struct {
	admission *admissionservice.AdmissionService
	store     *Store
}

type selectedSignal struct {
	Option  SkillOption
	Profile *admissionmodel.CapabilityProfile
}

func NewService(admission *admissionservice.AdmissionService, store *Store) *Service {
	return &Service{admission: admission, store: store}
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
	combinedTags = normalizeStrings(combinedTags)
	inferredChains := prioritizeInferredChains(inferChains(selectedSignals, combinedProfile))
	overview := &Overview{
		Options:         options,
		SelectedSkills:  selected,
		CombinedProfile: combinedProfile,
		CombinedRisks:   combinedRisks,
		CombinedTags:    combinedTags,
		Capabilities:    combinedProfile.ToDetectedCapabilities(),
		InferredChains:  inferredChains,
		Conclusion:      buildConclusion(selected, combinedProfile, combinedRisks, inferredChains),
	}
	runID, savedAt, err := s.saveOverview(selected, overview)
	if err != nil {
		return nil, err
	}
	overview.RunID = runID
	overview.SavedAt = savedAt
	return overview, nil
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

func (s *Service) saveOverview(selected []SkillOption, overview *Overview) (string, int64, error) {
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
		SelectedSkills: append([]string(nil), selectedIDs...),
		Overview:       toRunOverview(overview),
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	return runID, now, err
}

func buildSelectionKey(skillIDs []string) string {
	items := normalizeStrings(skillIDs)
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j] < items[i] {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
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
			Evidence:        append([]string(nil), item.Evidence...),
			AttackPath:      append([]string(nil), item.AttackPath...),
			MITRETechniques: append([]string(nil), item.MITRETechniques...),
			SourceSkills:    append([]RiskSourceSkill(nil), item.SourceSkills...),
		})
	}
	return out
}
