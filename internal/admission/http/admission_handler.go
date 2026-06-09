package http

import (
	"errors"
	"net/http"
	"strings"

	admissionmodel "skill-scanner/internal/admission/model"
	admissionservice "skill-scanner/internal/admission/service"
	admissionstore "skill-scanner/internal/admission/store"
)

type CurrentUserProvider func(r *http.Request) string

type AdmissionHandler struct {
	service     *admissionservice.AdmissionService
	currentUser CurrentUserProvider
}

type createSkillFromReportRequest struct {
	ReportID        string `json:"report_id"`
	DisplayName     string `json:"display_name"`
	Version         string `json:"version"`
	Description     string `json:"description"`
	ReviewSummary   string `json:"review_summary"`
	AdmissionStatus string `json:"admission_status"`
	ReviewDecision  string `json:"review_decision"`
}

func NewAdmissionHandler(service *admissionservice.AdmissionService, currentUser CurrentUserProvider) *AdmissionHandler {
	return &AdmissionHandler{service: service, currentUser: currentUser}
}

func (h *AdmissionHandler) CreateSkillFromReport(w http.ResponseWriter, r *http.Request) {
	if !requireMethods(w, r, http.MethodPost) {
		return
	}
	var req createSkillFromReportRequest
	if err := decodeStrictJSONBody(w, r, &req, 64<<10); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体格式错误"})
		return
	}
	out, err := h.service.CreateSkillFromReport(admissionservice.CreateSkillFromReportInput{
		ReportID:        req.ReportID,
		DisplayName:     req.DisplayName,
		Version:         req.Version,
		Description:     req.Description,
		ReviewSummary:   req.ReviewSummary,
		AdmissionStatus: admissionmodel.AdmissionStatus(req.AdmissionStatus),
		ReviewDecision:  admissionmodel.ReviewDecision(req.ReviewDecision),
		Operator:        strings.TrimSpace(h.currentUser(r)),
	})
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, admissionstore.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"skill_id": out.Skill.SkillID,
		"skill":    out.Skill,
		"profile":  out.Profile,
		"risks":    out.Risks,
	})
}
