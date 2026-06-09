package combination

import (
	"fmt"
	"testing"

	admissionmodel "skill-scanner/internal/admission/model"
)

func BenchmarkInferChains500Skills(b *testing.B) {
	selected, profile := buildBenchmarkSignals(500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = inferChains(selected, profile)
	}
}

func BenchmarkInferChains300Skills(b *testing.B) {
	selected, profile := buildBenchmarkSignals(300)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = inferChains(selected, profile)
	}
}

func buildBenchmarkSignals(n int) ([]selectedSignal, *admissionmodel.CapabilityProfile) {
	selected := make([]selectedSignal, 0, n)
	combined := &admissionmodel.CapabilityProfile{}
	for i := 0; i < n; i++ {
		p := &admissionmodel.CapabilityProfile{}
		switch i % 6 {
		case 0:
			p.NetworkAccess = true
			p.ExternalFetch = true
			p.Evidence = []string{fmt.Sprintf("scripts/run%d.py:10 | requests.get(url)", i)}
		case 1:
			p.CommandExec = true
			p.Evidence = []string{fmt.Sprintf("scripts/run%d.py:20 | os.system(cmd)", i)}
		case 2:
			p.SensitiveDataAccess = true
			p.FileRead = true
			p.Evidence = []string{fmt.Sprintf("scripts/run%d.py:12 | open('.env').read()", i)}
		case 3:
			p.FileWrite = true
			p.Persistence = true
			p.Evidence = []string{fmt.Sprintf("scripts/run%d.py:30 | writefile('/tmp/payload')", i)}
		case 4:
			p.DataCollection = true
			p.NetworkAccess = true
			p.Evidence = []string{fmt.Sprintf("scripts/run%d.py:40 | collect+upload", i)}
		default:
			p.PrivilegeUse = true
			p.CommandExec = true
			p.Evidence = []string{fmt.Sprintf("scripts/run%d.py:50 | sudo sh", i)}
		}
		p.Normalize()
		selected = append(selected, selectedSignal{Option: SkillOption{SkillID: fmt.Sprintf("skill-%d", i), DisplayName: fmt.Sprintf("Skill %d", i)}, Profile: p})
		mergeCapabilityProfile(combined, p)
	}
	combined.Normalize()
	return selected, combined
}
