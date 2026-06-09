package http

import (
	"errors"
	"net/http"
	"path"
	"strings"

	admissionservice "skill-scanner/internal/admission/service"
	admissionstore "skill-scanner/internal/admission/store"
)

type RegistryHandler struct {
	service *admissionservice.AdmissionService
}

func NewRegistryHandler(service *admissionservice.AdmissionService) *RegistryHandler {
	return &RegistryHandler{service: service}
}

func (h *RegistryHandler) ListSkills(w http.ResponseWriter, r *http.Request) {
	if !requireMethods(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	items, err := h.service.ListSkills("", 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (h *RegistryHandler) GetSkillDetail(w http.ResponseWriter, r *http.Request) {
	if !requireMethods(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	skillID := strings.TrimSpace(path.Base(r.URL.Path))
	if skillID == "" || skillID == "skills" || skillID == "." || skillID == "/" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无效技能ID"})
		return
	}
	detail, err := h.service.GetSkillDetail(skillID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, admissionstore.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, detail)
}
