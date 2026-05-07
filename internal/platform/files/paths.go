package files

import (
	"os"
	"path/filepath"
	"strings"
)

type DataPaths struct {
	DataDir          string
	ReportsDir       string
	AdmissionDir     string
	AdmissionSkills  string
	AdmissionRisks   string
	AdmissionProfile string
	AdmissionReviews string
	CombinationDir   string
	CombinationRuns  string
	RuleProfilesDir  string
	TasksDir         string
}

func NewDataPaths(dataDir string) DataPaths {
	return DataPaths{
		DataDir:          dataDir,
		ReportsDir:       filepath.Join(dataDir, "reports"),
		AdmissionDir:     filepath.Join(dataDir, "admission"),
		AdmissionSkills:  filepath.Join(dataDir, "admission", "skills.json"),
		AdmissionRisks:   filepath.Join(dataDir, "admission", "risks.json"),
		AdmissionProfile: filepath.Join(dataDir, "admission", "profiles.json"),
		AdmissionReviews: filepath.Join(dataDir, "admission", "review_records.json"),
		CombinationDir:   filepath.Join(dataDir, "combination"),
		CombinationRuns:  filepath.Join(dataDir, "combination", "runs.json"),
		RuleProfilesDir:  filepath.Join(dataDir, "users_rule_profiles"),
		TasksDir:         filepath.Join(dataDir, "tasks"),
	}
}

func EnsureDataDirs(paths DataPaths) error {
	for _, dir := range []string{paths.DataDir, paths.ReportsDir, paths.AdmissionDir, paths.CombinationDir, paths.RuleProfilesDir, paths.TasksDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return nil
}

func IsPathSafe(base, rel string) bool {
	clean := filepath.Clean(filepath.Join(base, rel))
	absBase, _ := filepath.Abs(base)
	absClean, _ := filepath.Abs(clean)
	if absBase == absClean {
		return true
	}
	return strings.HasPrefix(absClean, absBase+string(filepath.Separator))
}
