package combination

import (
	"fmt"
	"testing"

	admissionmodel "skill-scanner/internal/admission/model"
)

func BenchmarkBuildSelectionKeyBySkillCount(b *testing.B) {
	for _, size := range []int{10, 20, 50, 100} {
		skillIDs := buildBenchmarkSkillIDs(size)
		b.Run(fmt.Sprintf("skills_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = buildSelectionKey(skillIDs)
			}
		})
	}
}

func BenchmarkInferSemanticChainsBySkillCount(b *testing.B) {
	for _, size := range []int{10, 20, 50, 100} {
		selected, profile := buildSemanticBenchmarkSignals(size)
		known := []InferredChain{}
		b.Run(fmt.Sprintf("skills_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = inferSemanticChains(selected, profile, known)
			}
		})
	}
}

func buildBenchmarkSkillIDs(n int) []string {
	out := make([]string, 0, n)
	for i := n - 1; i >= 0; i-- {
		out = append(out, fmt.Sprintf("skill-%03d", i))
	}
	return out
}

func buildSemanticBenchmarkSignals(n int) ([]selectedSignal, *admissionmodel.CapabilityProfile) {
	selected := make([]selectedSignal, 0, n)
	combined := &admissionmodel.CapabilityProfile{}
	for i := 0; i < n; i++ {
		p := &admissionmodel.CapabilityProfile{}
		switch i % 5 {
		case 0:
			p.SensitiveDataAccess = true
			p.FileRead = true
			p.Evidence = []string{fmt.Sprintf("collect credential from /etc/passwd #%d", i)}
		case 1:
			p.FileWrite = true
			p.ExternalFetch = true
			p.Evidence = []string{fmt.Sprintf("write payload /tmp/drop-%d", i)}
		case 2:
			p.NetworkAccess = true
			p.Evidence = []string{fmt.Sprintf("http post outbound #%d", i)}
		case 3:
			p.CommandExec = true
			p.Evidence = []string{fmt.Sprintf("exec shell subprocess #%d", i)}
		default:
			p.Persistence = true
			p.Evidence = []string{fmt.Sprintf("cron startup autorun #%d", i)}
		}
		p.Normalize()
		selected = append(selected, selectedSignal{Option: SkillOption{SkillID: fmt.Sprintf("skill-%d", i), DisplayName: fmt.Sprintf("Skill %d", i)}, Profile: p})
		mergeCapabilityProfile(combined, p)
	}
	combined.CapabilityScopes = map[string][]string{
		"file_read":      {"sensitive_system_file"},
		"network_access": {"internet"},
	}
	combined.CommandExec = true
	combined.Normalize()
	return selected, combined
}
