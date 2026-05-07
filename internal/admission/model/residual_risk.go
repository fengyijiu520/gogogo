package model

import (
	"errors"
	"strings"
)

type ResidualRisk struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Level       string `json:"level"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Condition   string `json:"condition"`
	Mitigation  string `json:"mitigation"`
}

func (r *ResidualRisk) Normalize() {
	if r == nil {
		return
	}
	r.ID = strings.TrimSpace(r.ID)
	r.Category = strings.TrimSpace(r.Category)
	r.Level = strings.TrimSpace(r.Level)
	r.Title = strings.TrimSpace(r.Title)
	r.Description = strings.TrimSpace(r.Description)
	r.Condition = strings.TrimSpace(r.Condition)
	r.Mitigation = strings.TrimSpace(r.Mitigation)
}

func (r *ResidualRisk) Validate() error {
	if r == nil {
		return errors.New("risk is nil")
	}
	if r.Title == "" {
		return errors.New("risk title is required")
	}
	return nil
}
