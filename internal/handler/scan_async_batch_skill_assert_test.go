package handler

import (
	"strings"
	"testing"

	"skill-scanner/internal/review"
)

type structuredExpectation struct {
	category            string
	securityVerdict     string
	declarationVerdict  string
	secondary           bool
}

func assertStructuredFindingMatrix(t *testing.T, refined review.Result, structured []review.StructuredFinding, want structuredExpectation) {
	t.Helper()
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	got := structured[0]
	if got.Category != want.category {
		t.Fatalf("expected category %q, got %+v", want.category, got)
	}
	if got.SecurityVerdict != want.securityVerdict {
		t.Fatalf("expected security verdict %q, got %+v", want.securityVerdict, got)
	}
	if got.DeclarationVerdict != want.declarationVerdict {
		t.Fatalf("expected declaration verdict %q, got %+v", want.declarationVerdict, got)
	}
	primary, secondary := splitStructuredFindingsForDisplay(structured)
	if want.secondary {
		if len(primary) != 0 || len(secondary) != 1 {
			t.Fatalf("expected finding in secondary bucket, primary=%+v secondary=%+v", primary, secondary)
		}
		html := renderStructuredFindingsSection(review.Result{StructuredFindings: structured, ReviewAgentVerdicts: refined.ReviewAgentVerdicts})
		if !strings.Contains(html, "展开低优先级文档与交付提示（1 条）") {
			t.Fatalf("expected secondary disclosure rendered, got %s", html)
		}
		return
	}
	if len(primary) != 1 || len(secondary) != 0 {
		t.Fatalf("expected finding stays in primary bucket, primary=%+v secondary=%+v", primary, secondary)
	}
}
