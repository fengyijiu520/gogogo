package handler

import (
	"fmt"

	"skill-scanner/internal/evaluator"
	"skill-scanner/internal/review"
)

func updateScanTaskPhase(taskID string, phase review.Phase, message, progressKey string) {
	taskStore.update(taskID, func(t *scanTask) {
		t.Status = phase
		t.Message = message
		if progressKey != "" {
			t.Progress[progressKey] = true
		}
	})
}

func updateScanTaskMessage(taskID, message, currentRule string) {
	taskStore.update(taskID, func(t *scanTask) {
		t.Message = message
		if currentRule != "" {
			t.CurrentRule = currentRule
		}
	})
}

func updateScanTaskMessageWithReviewTrace(taskID, message string, trace *review.ReviewTrace) {
	taskStore.update(taskID, func(t *scanTask) {
		t.Message = message
		if trace != nil {
			t.ReviewTrace = cloneScanTaskReviewTrace(trace)
		}
	})
}

func failScanTaskWithPDFTrace(taskID string, err error, pdfTrace pdfRenderTrace) {
	taskStore.update(taskID, func(t *scanTask) {
		t.Status = review.PhaseFailed
		t.Message = err.Error()
		t.PDFTrace = pdfTrace.TraceMessage()
		t.PDFEngine = pdfTrace.Engine
		t.PDFFontFile = pdfTrace.FontFile
	})
}

func completeScanTaskWithReport(taskID, reportID string, findingsCount int, base baseScanOutput, refined review.Result, pdfTrace pdfRenderTrace) {
	highRisk, mediumRisk, lowRisk := displayRiskCounts(refined)
	taskStore.update(taskID, func(t *scanTask) {
		t.Status = review.PhaseDone
		t.Message = fmt.Sprintf("扫描完成（高:%d 中:%d 低:%d）", highRisk, mediumRisk, lowRisk)
		t.ReportID = reportID
		t.FindingCount = findingsCount
		t.HighRisk = highRisk
		t.MediumRisk = mediumRisk
		t.LowRisk = lowRisk
		t.PDFTrace = pdfTrace.TraceMessage()
		t.PDFEngine = pdfTrace.Engine
		t.PDFFontFile = pdfTrace.FontFile
		t.DetectionErrors = append([]evaluator.DetectionError{}, base.detectionErrors...)
	})
}
