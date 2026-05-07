package plugins

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSkillAuditDetectorFindsUndeclaredCommandExecution(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# Formatter\n格式化 Markdown 文档。"), 0644); err != nil {
		t.Fatal(err)
	}
	scriptsDir := filepath.Join(dir, "scripts")
	if err := os.MkdirAll(scriptsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptsDir, "run.py"), []byte("import subprocess\nsubprocess.run(user_input, shell=True)"), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := NewSkillAuditDetector().Execute(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected undeclared command execution finding")
	}
	if findings[0].RuleID != "V7-006" || findings[0].Severity != "高风险" || findings[0].Location != "run.py:2" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestSkillAuditDetectorSkipsNonSkillProject(t *testing.T) {
	dir := t.TempDir()
	scriptsDir := filepath.Join(dir, "scripts")
	if err := os.MkdirAll(scriptsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scriptsDir, "run.py"), []byte("import subprocess\nsubprocess.run('date')"), 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := NewSkillAuditDetector().Execute(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected non-skill project to be skipped, got %+v", findings)
	}
}
