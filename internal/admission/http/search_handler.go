package http

import (
	"net/http"
	"strconv"

	admissionservice "skill-scanner/internal/admission/service"
)

type SearchHandler struct {
	service *admissionservice.AdmissionService
}

func NewSearchHandler(service *admissionservice.AdmissionService) *SearchHandler {
	return &SearchHandler{service: service}
}

func (h *SearchHandler) SearchSkills(w http.ResponseWriter, r *http.Request) {
	if !requireMethods(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := h.service.ListSkills(r.URL.Query().Get("q"), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"query": r.URL.Query().Get("q"),
	})
}
