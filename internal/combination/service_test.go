package combination

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	admissionmodel "skill-scanner/internal/admission/model"
	admissionservice "skill-scanner/internal/admission/service"
	admissionstore "skill-scanner/internal/admission/store"
	"skill-scanner/internal/models"
	"skill-scanner/internal/review"
)

type fakeReportLookup struct {
	reports    map[string]*models.Report
	reportsDir string
}

func (f fakeReportLookup) GetReport(id string) *models.Report {
	return f.reports[id]
}

func (f fakeReportLookup) ReportsDir() string {
	return f.reportsDir
}

func TestBuildOverviewAggregatesSelectedSkills(t *testing.T) {
	dataDir := t.TempDir()
	reportsDir := filepath.Join(dataDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("mkdir reports dir: %v", err)
	}
	skills, err := admissionstore.NewSkillStore(dataDir)
	if err != nil {
		t.Fatalf("new skill store: %v", err)
	}
	profiles, err := admissionstore.NewProfileStore(dataDir)
	if err != nil {
		t.Fatalf("new profile store: %v", err)
	}
	risks, err := admissionstore.NewRiskStore(dataDir)
	if err != nil {
		t.Fatalf("new risk store: %v", err)
	}
	reviews, err := admissionstore.NewReviewRecordStore(dataDir)
	if err != nil {
		t.Fatalf("new review store: %v", err)
	}
	reportA := writeReportFixture(t, reportsDir, "report-a", "skill-a.zip", review.Result{Behavior: review.BehaviorProfile{
		NetworkTargets: []string{"https://example.com/a"},
		CredentialIOCs: []string{"/root/.netrc"},
		BehaviorChains: []string{"下载=1, 执行=0, 外联=1"},
	}})
	reportB := writeReportFixture(t, reportsDir, "report-b", "skill-b.zip", review.Result{Behavior: review.BehaviorProfile{
		ExecTargets:    []string{"exec.Command"},
		ExecuteIOCs:    []string{"exec.Command"},
		BehaviorChains: []string{"下载=1, 执行=1, 外联=1"},
	}})
	lookup := fakeReportLookup{
		reports: map[string]*models.Report{
			reportA.ID: reportA,
			reportB.ID: reportB,
		},
		reportsDir: reportsDir,
	}
	combinationStore, err := NewStore(dataDir)
	if err != nil {
		t.Fatalf("new combination store: %v", err)
	}
	admissionSvc := admissionservice.NewAdmissionService(lookup, skills, profiles, risks, reviews, admissionservice.NewProfileBuilder())
	first := createSkillFixture(t, admissionSvc, reportA.ID, reportA.FileName)
	second := createSkillFixture(t, admissionSvc, reportB.ID, reportB.FileName)

	overview, err := NewService(admissionSvc, combinationStore).BuildOverview([]string{first.SkillID, second.SkillID}, 200)
	if err != nil {
		t.Fatalf("build overview: %v", err)
	}
	if overview.RunID == "" || overview.SavedAt == 0 {
		t.Fatalf("expected saved run metadata, got %+v", overview)
	}
	stored, ok := combinationStore.GetBySelectionKey(buildSelectionKey([]string{first.SkillID, second.SkillID}))
	if !ok || stored == nil {
		t.Fatalf("expected saved combination run")
	}
	if stored.RunID != overview.RunID {
		t.Fatalf("expected stored run id match, got %+v %+v", stored, overview)
	}
	if len(overview.Options) != 2 {
		t.Fatalf("expected 2 options, got %d", len(overview.Options))
	}
	if len(overview.SelectedSkills) != 2 {
		t.Fatalf("expected 2 selected skills, got %d", len(overview.SelectedSkills))
	}
	if !overview.CombinedProfile.NetworkAccess || !overview.CombinedProfile.CommandExec {
		t.Fatalf("expected merged capabilities, got %+v", overview.CombinedProfile)
	}
	if !contains(overview.Capabilities, "network_access") || !contains(overview.Capabilities, "command_exec") {
		t.Fatalf("expected merged capability summary, got %+v", overview.Capabilities)
	}
	if !contains(overview.CombinedTags, "outbound_network") || !contains(overview.CombinedTags, "command_execution") {
		t.Fatalf("expected merged risk tags, got %+v", overview.CombinedTags)
	}
	if countRiskTitle(overview.CombinedRisks, "存在高风险行为链摘要") != 1 {
		t.Fatalf("expected deduped behavior-chain risk once, got %+v", overview.CombinedRisks)
	}
	behaviorChain := findCombinedRiskByTitle(overview.CombinedRisks, "存在高风险行为链摘要")
	if behaviorChain == nil {
		t.Fatalf("expected behavior-chain risk detail, got %+v", overview.CombinedRisks)
	}
	if len(behaviorChain.SourceSkills) != 2 {
		t.Fatalf("expected 2 source skills for shared risk, got %+v", behaviorChain.SourceSkills)
	}
	if overview.Conclusion.RiskLevel != "high" {
		t.Fatalf("expected high risk conclusion, got %+v", overview.Conclusion)
	}
	if overview.Conclusion.HighRiskCount == 0 {
		t.Fatalf("expected high risk count populated, got %+v", overview.Conclusion)
	}
	if overview.Conclusion.SelectedSkillCount != 2 {
		t.Fatalf("expected selected skill count 2, got %+v", overview.Conclusion)
	}
	if strings.TrimSpace(overview.Conclusion.Recommendation) == "" {
		t.Fatalf("expected recommendation text, got %+v", overview.Conclusion)
	}
	remoteChain := findInferredChainByTitle(overview.InferredChains, "潜在远程指令执行链")
	if remoteChain != nil {
		t.Fatalf("expected remote command chain folded by full attack chain, got %+v", overview.InferredChains)
	}
	fullChain := findInferredChainByTitle(overview.InferredChains, "潜在完整攻击链")
	if fullChain == nil || !contains(fullChain.Evidence, "https://example.com/a") || !contains(fullChain.Evidence, "exec.Command") {
		t.Fatalf("expected full chain observed evidence, got %+v", fullChain)
	}
	if len(overview.InferredChains) == 0 || overview.InferredChains[0].ID != "full-attack-chain" {
		t.Fatalf("expected full attack chain ranked first, got %+v", overview.InferredChains)
	}
}

func TestBuildOverviewFromRealisticFixtures(t *testing.T) {
	dataDir := t.TempDir()
	reportsDir := filepath.Join(dataDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("mkdir reports dir: %v", err)
	}
	skills, err := admissionstore.NewSkillStore(dataDir)
	if err != nil {
		t.Fatalf("new skill store: %v", err)
	}
	profiles, err := admissionstore.NewProfileStore(dataDir)
	if err != nil {
		t.Fatalf("new profile store: %v", err)
	}
	risks, err := admissionstore.NewRiskStore(dataDir)
	if err != nil {
		t.Fatalf("new risk store: %v", err)
	}
	reviews, err := admissionstore.NewReviewRecordStore(dataDir)
	if err != nil {
		t.Fatalf("new review store: %v", err)
	}
	lookup := fakeReportLookup{
		reports:    map[string]*models.Report{},
		reportsDir: reportsDir,
	}
	for _, fixture := range []struct {
		reportID  string
		fileName  string
		behavior  review.BehaviorProfile
		display   string
		desc      string
	}{
		{
			reportID: "fixture-network",
			fileName: "network-observer.zip",
			behavior: review.BehaviorProfile{
				NetworkTargets: []string{"https://example.com/api", "https://backup.example.com/upload"},
				CredentialIOCs: []string{"/root/.netrc"},
				BehaviorChains: []string{"下载=1, 执行=0, 外联=1"},
			},
			display: "Network Observer",
			desc:    "采集网络与凭据信号",
		},
		{
			reportID: "fixture-exec",
			fileName: "command-runner.zip",
			behavior: review.BehaviorProfile{
				ExecTargets:    []string{"exec.Command", "sh -c"},
				ExecuteIOCs:    []string{"exec.Command", "os.WriteFile('/tmp/dropper.bin')"},
				BehaviorChains: []string{"下载=1, 执行=1, 外联=1"},
				SequenceAlerts: []string{"命中下载后执行时序"},
			},
			display: "Command Runner",
			desc:    "执行本地命令并落地文件",
		},
	} {
		report := writeReportFixture(t, reportsDir, fixture.reportID, fixture.fileName, review.Result{Behavior: fixture.behavior})
		lookup.reports[report.ID] = report
	}
	combinationStore, err := NewStore(dataDir)
	if err != nil {
		t.Fatalf("new combination store: %v", err)
	}
	admissionSvc := admissionservice.NewAdmissionService(lookup, skills, profiles, risks, reviews, admissionservice.NewProfileBuilder())
	first := createSkillFixtureWithMeta(t, admissionSvc, "fixture-network", "Network Observer", "采集网络与凭据信号")
	second := createSkillFixtureWithMeta(t, admissionSvc, "fixture-exec", "Command Runner", "执行本地命令并落地文件")

	overview, err := NewService(admissionSvc, combinationStore).BuildOverview([]string{first.SkillID, second.SkillID}, 50)
	if err != nil {
		t.Fatalf("build overview from realistic fixtures: %v", err)
	}
	if overview.Conclusion.RiskLevel != "high" {
		t.Fatalf("expected high risk conclusion, got %+v", overview.Conclusion)
	}
	if !overview.CombinedProfile.NetworkAccess || !overview.CombinedProfile.CommandExec || !overview.CombinedProfile.SensitiveDataAccess {
		t.Fatalf("expected merged realistic capabilities, got %+v", overview.CombinedProfile)
	}
	for _, want := range []string{"https://example.com/api", "/root/.netrc", "exec.Command", "命中下载后执行时序"} {
		if !contains(overview.CombinedProfile.Evidence, want) {
			t.Fatalf("expected evidence %q in %+v", want, overview.CombinedProfile.Evidence)
		}
	}
	if len(overview.InferredChains) == 0 || overview.InferredChains[0].ID != "full-attack-chain" {
		t.Fatalf("expected full attack chain ranked first, got %+v", overview.InferredChains)
	}
	if chain := findInferredChainByTitle(overview.InferredChains, "潜在远程指令执行链"); chain != nil {
		t.Fatalf("expected remote command chain folded by full attack chain, got %+v", overview.InferredChains)
	}
	if len(overview.SelectedSkills) != 2 || overview.SelectedSkills[0].DisplayName == "" || overview.SelectedSkills[1].DisplayName == "" {
		t.Fatalf("expected selected skill metadata preserved, got %+v", overview.SelectedSkills)
	}
	if countRiskTitle(overview.CombinedRisks, "存在高风险行为链摘要") != 1 {
		t.Fatalf("expected shared behavior-chain risk deduped once, got %+v", overview.CombinedRisks)
	}
	if stored, ok := combinationStore.GetBySelectionKey(buildSelectionKey([]string{first.SkillID, second.SkillID})); !ok || stored == nil {
		t.Fatalf("expected overview persisted for realistic fixtures")
	}
	if !fixtureDescriptionsSanity(first, second) {
		t.Fatalf("expected imported realistic skills keep descriptions, got %+v %+v", first, second)
	}
}

func TestBuildOverviewFromWeakRealisticFixturesStaysMediumWithoutChains(t *testing.T) {
	dataDir := t.TempDir()
	reportsDir := filepath.Join(dataDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("mkdir reports dir: %v", err)
	}
	skills, err := admissionstore.NewSkillStore(dataDir)
	if err != nil {
		t.Fatalf("new skill store: %v", err)
	}
	profiles, err := admissionstore.NewProfileStore(dataDir)
	if err != nil {
		t.Fatalf("new profile store: %v", err)
	}
	risks, err := admissionstore.NewRiskStore(dataDir)
	if err != nil {
		t.Fatalf("new risk store: %v", err)
	}
	reviews, err := admissionstore.NewReviewRecordStore(dataDir)
	if err != nil {
		t.Fatalf("new review store: %v", err)
	}
	lookup := fakeReportLookup{
		reports: map[string]*models.Report{
			"weak-network": writeReportFixture(t, reportsDir, "weak-network", "weak-network.zip", review.Result{Behavior: review.BehaviorProfile{
				NetworkTargets: []string{"https://docs.example.com/reference"},
			}}),
			"weak-exec": writeReportFixture(t, reportsDir, "weak-exec", "weak-exec.zip", review.Result{Behavior: review.BehaviorProfile{
				FileTargets: []string{"docs/example-config.json"},
			}}),
		},
		reportsDir: reportsDir,
	}
	combinationStore, err := NewStore(dataDir)
	if err != nil {
		t.Fatalf("new combination store: %v", err)
	}
	admissionSvc := admissionservice.NewAdmissionService(lookup, skills, profiles, risks, reviews, admissionservice.NewProfileBuilder())
	first := createSkillFixtureWithMeta(t, admissionSvc, "weak-network", "Weak Network Doc", "仅声明网络访问示例")
	second := createSkillFixtureWithMeta(t, admissionSvc, "weak-exec", "Weak File Doc", "仅声明文件读取示例")

	overview, err := NewService(admissionSvc, combinationStore).BuildOverview([]string{first.SkillID, second.SkillID}, 50)
	if err != nil {
		t.Fatalf("build overview from weak realistic fixtures: %v", err)
	}
	if overview.Conclusion.RiskLevel != "medium" {
		t.Fatalf("expected medium risk from pure capability overlap, got %+v", overview.Conclusion)
	}
	if len(overview.InferredChains) != 0 {
		t.Fatalf("expected no inferred chains for weak realistic fixtures, got %+v", overview.InferredChains)
	}
	if !overview.CombinedProfile.NetworkAccess || !overview.CombinedProfile.FileRead {
		t.Fatalf("expected overlapping capabilities preserved, got %+v", overview.CombinedProfile)
	}
	for _, unwanted := range []string{"exec.Command", "/root/.netrc", "命中下载后执行时序"} {
		if contains(overview.CombinedProfile.Evidence, unwanted) {
			t.Fatalf("expected weak realistic fixture not to include strong evidence %q in %+v", unwanted, overview.CombinedProfile.Evidence)
		}
	}
	if overview.Conclusion.HighConfidenceChains != 0 {
		t.Fatalf("expected no high confidence chain count, got %+v", overview.Conclusion)
	}
}

func TestMergeCapabilityProfile(t *testing.T) {
	dst := &admissionmodel.CapabilityProfile{NetworkAccess: true, Tags: []string{"network_access"}}
	src := &admissionmodel.CapabilityProfile{CommandExec: true, Evidence: []string{"exec.Command"}}

	mergeCapabilityProfile(dst, src)

	if !dst.NetworkAccess || !dst.CommandExec {
		t.Fatalf("expected merged capability flags, got %+v", dst)
	}
	if len(dst.Tags) != 1 || dst.Tags[0] != "network_access" {
		t.Fatalf("expected tags preserved, got %+v", dst.Tags)
	}
	if len(dst.Evidence) != 1 || dst.Evidence[0] != "exec.Command" {
		t.Fatalf("expected evidence appended, got %+v", dst.Evidence)
	}
}

func TestNormalizeStrings(t *testing.T) {
	out := normalizeStrings([]string{" outbound_network ", "", "outbound_network", "command_execution"})
	if len(out) != 2 {
		t.Fatalf("expected deduped normalized strings, got %+v", out)
	}
	if out[0] != "outbound_network" || out[1] != "command_execution" {
		t.Fatalf("unexpected normalized output: %+v", out)
	}
}

func TestBuildConclusionEmptySelection(t *testing.T) {
	conclusion := buildConclusion(nil, &admissionmodel.CapabilityProfile{}, nil, nil)
	if conclusion.RiskLabel != "待分析" {
		t.Fatalf("expected pending conclusion, got %+v", conclusion)
	}
	if !strings.Contains(conclusion.Recommendation, "请选择") {
		t.Fatalf("expected guidance recommendation, got %+v", conclusion)
	}
}

func TestBuildConclusionKeepsPureCapabilityOverlapAtMedium(t *testing.T) {
	profile := &admissionmodel.CapabilityProfile{NetworkAccess: true, CommandExec: true, SensitiveDataAccess: true}
	conclusion := buildConclusion([]SkillOption{{SkillID: "a"}, {SkillID: "b"}}, profile, nil, nil)
	if conclusion.RiskLevel != "medium" {
		t.Fatalf("expected medium risk for pure capability overlap, got %+v", conclusion)
	}
	if conclusion.HighConfidenceChains != 0 {
		t.Fatalf("expected no high confidence chains, got %+v", conclusion)
	}
}

func TestBuildConclusionUsesHighConfidenceChainsForHighRisk(t *testing.T) {
	profile := &admissionmodel.CapabilityProfile{NetworkAccess: true, CommandExec: true}
	chains := []InferredChain{{
		ID:           "remote-command-chain",
		Level:        "high",
		Evidence:     []string{"https://example.com/a", "exec.Command"},
		SourceSkills: []RiskSourceSkill{{SkillID: "a"}, {SkillID: "b"}},
	}}
	conclusion := buildConclusion([]SkillOption{{SkillID: "a"}, {SkillID: "b"}}, profile, nil, chains)
	if conclusion.RiskLevel != "high" {
		t.Fatalf("expected high risk from high-confidence chain, got %+v", conclusion)
	}
	if conclusion.HighConfidenceChains != 1 {
		t.Fatalf("expected one high-confidence chain, got %+v", conclusion)
	}
}

func TestInferChainsFullAttackChain(t *testing.T) {
	selected := []selectedSignal{
		{Option: SkillOption{SkillID: "A", DisplayName: "Skill A"}, Profile: &admissionmodel.CapabilityProfile{NetworkAccess: true, SensitiveDataAccess: true, Evidence: []string{"https://example.com/a", "/root/.netrc"}}},
		{Option: SkillOption{SkillID: "B", DisplayName: "Skill B"}, Profile: &admissionmodel.CapabilityProfile{CommandExec: true, FileWrite: true, Evidence: []string{"exec.Command", "os.WriteFile('/tmp/dropper.bin')", "dropper.bin"}}},
	}
	profile := &admissionmodel.CapabilityProfile{
		NetworkAccess:       true,
		CommandExec:         true,
		SensitiveDataAccess: true,
		FileWrite:           true,
	}
	chains := inferChains(selected, profile)
	if findInferredChainByTitle(chains, "潜在完整攻击链") == nil {
		t.Fatalf("expected full attack chain inferred, got %+v", chains)
	}
	if findInferredChainByTitle(chains, "潜在落地执行链") == nil {
		t.Fatalf("expected write exec chain inferred, got %+v", chains)
	}
	fullChain := findInferredChainByTitle(chains, "潜在完整攻击链")
	if fullChain == nil || !contains(fullChain.Evidence, "https://example.com/a") || !contains(fullChain.Evidence, "exec.Command") {
		t.Fatalf("expected full chain evidence, got %+v", fullChain)
	}
}

func TestInferChainsSkipsWeakCapabilityOnlyOverlap(t *testing.T) {
	selected := []selectedSignal{
		{Option: SkillOption{SkillID: "A", DisplayName: "Skill A"}, Profile: &admissionmodel.CapabilityProfile{NetworkAccess: true, Evidence: []string{"note only"}}},
		{Option: SkillOption{SkillID: "B", DisplayName: "Skill B"}, Profile: &admissionmodel.CapabilityProfile{CommandExec: true, Evidence: []string{"misc only"}}},
	}
	profile := &admissionmodel.CapabilityProfile{NetworkAccess: true, CommandExec: true}
	chains := inferChains(selected, profile)
	if len(chains) != 0 {
		t.Fatalf("expected no inferred chain for weak capability-only overlap, got %+v", chains)
	}
}

func TestInferChainsRequiresCrossSkillEvidenceSupport(t *testing.T) {
	selected := []selectedSignal{
		{Option: SkillOption{SkillID: "A", DisplayName: "Skill A"}, Profile: &admissionmodel.CapabilityProfile{NetworkAccess: true, Evidence: []string{"https://example.com/a"}}},
		{Option: SkillOption{SkillID: "B", DisplayName: "Skill B"}, Profile: &admissionmodel.CapabilityProfile{CommandExec: true, Evidence: []string{"unrelated text"}}},
	}
	profile := &admissionmodel.CapabilityProfile{NetworkAccess: true, CommandExec: true}
	chains := inferChains(selected, profile)
	if len(chains) != 0 {
		t.Fatalf("expected no inferred chain without cross-skill evidence support, got %+v", chains)
	}
}

func TestInferChainsRegressionSamples(t *testing.T) {
	tests := []struct {
		name      string
		selected  []selectedSignal
		profile   *admissionmodel.CapabilityProfile
		wantChain []string
	}{
		{
			name: "弱能力重叠不应成链",
			selected: []selectedSignal{
				{Option: SkillOption{SkillID: "A", DisplayName: "Skill A"}, Profile: &admissionmodel.CapabilityProfile{NetworkAccess: true, Evidence: []string{"note only"}}},
				{Option: SkillOption{SkillID: "B", DisplayName: "Skill B"}, Profile: &admissionmodel.CapabilityProfile{CommandExec: true, Evidence: []string{"misc only"}}},
			},
			profile:   &admissionmodel.CapabilityProfile{NetworkAccess: true, CommandExec: true},
			wantChain: nil,
		},
		{
			name: "缺少跨技能证据不应成链",
			selected: []selectedSignal{
				{Option: SkillOption{SkillID: "A", DisplayName: "Skill A"}, Profile: &admissionmodel.CapabilityProfile{NetworkAccess: true, Evidence: []string{"https://example.com/a"}}},
				{Option: SkillOption{SkillID: "B", DisplayName: "Skill B"}, Profile: &admissionmodel.CapabilityProfile{CommandExec: true, Evidence: []string{"unrelated text"}}},
			},
			profile:   &admissionmodel.CapabilityProfile{NetworkAccess: true, CommandExec: true},
			wantChain: nil,
		},
		{
			name: "单技能强写入执行证据允许落地执行链",
			selected: []selectedSignal{
				{Option: SkillOption{SkillID: "A", DisplayName: "Skill A"}, Profile: &admissionmodel.CapabilityProfile{FileWrite: true, CommandExec: true, Evidence: []string{"exec.Command", "os.WriteFile('/tmp/dropper.bin')", "dropper.bin"}}},
				{Option: SkillOption{SkillID: "B", DisplayName: "Skill B"}, Profile: &admissionmodel.CapabilityProfile{NetworkAccess: true, Evidence: []string{"https://example.com/a"}}},
			},
			profile:   &admissionmodel.CapabilityProfile{FileWrite: true, CommandExec: true, NetworkAccess: true},
			wantChain: []string{"write-exec-chain"},
		},
		{
			name: "跨技能强证据允许完整攻击链",
			selected: []selectedSignal{
				{Option: SkillOption{SkillID: "A", DisplayName: "Skill A"}, Profile: &admissionmodel.CapabilityProfile{NetworkAccess: true, SensitiveDataAccess: true, Evidence: []string{"https://example.com/a", "/root/.netrc"}}},
				{Option: SkillOption{SkillID: "B", DisplayName: "Skill B"}, Profile: &admissionmodel.CapabilityProfile{CommandExec: true, Evidence: []string{"exec.Command"}}},
			},
			profile:   &admissionmodel.CapabilityProfile{NetworkAccess: true, SensitiveDataAccess: true, CommandExec: true},
			wantChain: []string{"remote-command-chain", "full-attack-chain"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chains := inferChains(tc.selected, tc.profile)
			if len(tc.wantChain) == 0 {
				if len(chains) != 0 {
					t.Fatalf("expected no chains, got %+v", chains)
				}
				return
			}
			for _, want := range tc.wantChain {
				found := false
				for _, chain := range chains {
					if chain.ID == want {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("expected chain %s in %+v", want, chains)
				}
			}
		})
	}
}

func TestPrioritizeInferredChains(t *testing.T) {
	chains := prioritizeInferredChains([]InferredChain{
		{ID: "remote-command-chain", Title: "潜在远程指令执行链"},
		{ID: "full-attack-chain", Title: "潜在完整攻击链"},
		{ID: "sensitive-exfiltration", Title: "潜在敏感数据外发链"},
		{ID: "write-exec-chain", Title: "潜在落地执行链"},
	})
	if len(chains) != 2 {
		t.Fatalf("expected folded chains length 2, got %+v", chains)
	}
	if chains[0].ID != "full-attack-chain" || chains[1].ID != "write-exec-chain" {
		t.Fatalf("expected prioritized chain order, got %+v", chains)
	}
}

func TestBuildSelectionKeyStableOrder(t *testing.T) {
	left := buildSelectionKey([]string{"skill-b", "skill-a", "skill-a"})
	right := buildSelectionKey([]string{"skill-a", "skill-b"})
	if left == "" || right == "" {
		t.Fatalf("expected non-empty selection key")
	}
	if left != right {
		t.Fatalf("expected stable selection key, got %q != %q", left, right)
	}
}

func TestStoreSaveUpdatesExistingRecord(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	record := &RunRecord{
		RunID:          "run-1",
		SelectionKey:   "sel-1",
		SelectedSkills: []string{"a", "b"},
		Overview: RunOverview{
			RiskLevel:    "medium",
			Capabilities: []string{"network_access"},
		},
		CreatedAt: 100,
		UpdatedAt: 100,
	}
	if err := store.Save(record); err != nil {
		t.Fatalf("save initial: %v", err)
	}
	updated := &RunRecord{
		RunID:          "run-1",
		SelectionKey:   "sel-1",
		SelectedSkills: []string{"a", "b"},
		Overview: RunOverview{
			RiskLevel:    "high",
			Capabilities: []string{"network_access", "command_exec"},
		},
		CreatedAt: 999,
		UpdatedAt: 200,
	}
	if err := store.Save(updated); err != nil {
		t.Fatalf("save update: %v", err)
	}
	stored, ok := store.GetBySelectionKey("sel-1")
	if !ok || stored == nil {
		t.Fatalf("expected stored record")
	}
	if stored.CreatedAt != 100 {
		t.Fatalf("expected created_at preserved, got %+v", stored)
	}
	if stored.UpdatedAt != 200 || stored.Overview.RiskLevel != "high" {
		t.Fatalf("expected updated record persisted, got %+v", stored)
	}
}

func writeReportFixture(t *testing.T, reportsDir, reportID, fileName string, result review.Result) *models.Report {
	t.Helper()
	jsonName := reportID + ".json"
	data, err := json.Marshal(struct {
		Result review.Result `json:"result"`
	}{Result: result})
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if err := os.WriteFile(filepath.Join(reportsDir, jsonName), data, 0644); err != nil {
		t.Fatalf("write fixture json: %v", err)
	}
	return &models.Report{
		ID:       reportID,
		FileName: fileName,
		FilePath: filepath.Join(reportsDir, fileName),
		JSONPath: jsonName,
	}
}

func createSkillFixture(t *testing.T, svc *admissionservice.AdmissionService, reportID, fileName string) *admissionmodel.AdmissionSkill {
	t.Helper()
	return createSkillFixtureWithMeta(t, svc, reportID, strings.TrimSuffix(fileName, filepath.Ext(fileName)), "测试技能")
}

func createSkillFixtureWithMeta(t *testing.T, svc *admissionservice.AdmissionService, reportID, displayName, description string) *admissionmodel.AdmissionSkill {
	t.Helper()
	out, err := svc.CreateSkillFromReport(admissionservice.CreateSkillFromReportInput{
		ReportID:        reportID,
		DisplayName:     displayName,
		Description:     description,
		AdmissionStatus: admissionmodel.AdmissionStatusApproved,
		ReviewDecision:  admissionmodel.ReviewDecisionPass,
		ReviewSummary:   "测试导入",
		Operator:        "admin",
	})
	if err != nil {
		t.Fatalf("create skill: %v", err)
	}
	return out.Skill
}

func fixtureDescriptionsSanity(skills ...*admissionmodel.AdmissionSkill) bool {
	for _, skill := range skills {
		if skill == nil || strings.TrimSpace(skill.Description) == "" {
			return false
		}
	}
	return true
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func countRiskTitle(items []CombinedRisk, title string) int {
	count := 0
	for _, item := range items {
		if item.Risk.Title == title {
			count++
		}
	}
	return count
}

func findCombinedRiskByTitle(items []CombinedRisk, title string) *CombinedRisk {
	for i := range items {
		if items[i].Risk.Title == title {
			return &items[i]
		}
	}
	return nil
}

func findInferredChainByTitle(items []InferredChain, title string) *InferredChain {
	for i := range items {
		if items[i].Title == title {
			return &items[i]
		}
	}
	return nil
}
