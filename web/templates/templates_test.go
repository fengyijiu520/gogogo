package templates

import (
	"strings"
	"testing"
)

func TestScanTemplateDoesNotAutoRedirectToReport(t *testing.T) {
	if strings.Contains(ScanHTML, "window.location.href = targetURL") {
		t.Fatalf("expected scan page to avoid auto redirect on completion")
	}
	if !strings.Contains(ScanHTML, "概要：") {
		t.Fatalf("expected scan page to show completion summary")
	}
}
