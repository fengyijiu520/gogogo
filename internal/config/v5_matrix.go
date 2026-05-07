package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// V5Matrix defines evaluability mapping for V5 assessment items.
type V5Matrix struct {
	Version string         `yaml:"version"`
	Items   []V5MatrixItem `yaml:"items"`
}

// V5MatrixItem defines one V5 checklist item and how system handles it.
type V5MatrixItem struct {
	ID             string `yaml:"id"`
	Domain         string `yaml:"domain"`
	Name           string `yaml:"name"`
	EvaluationMode string `yaml:"evaluation_mode"` // auto | manual
	MappingType    string `yaml:"mapping_type"`    // rule | runtime | manual
	MappingID      string `yaml:"mapping_id"`
}

// LoadV5Matrix loads V5 matrix config from yaml file.
func LoadV5Matrix(path string) (*V5Matrix, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var matrix V5Matrix
	if err := yaml.Unmarshal(data, &matrix); err != nil {
		return nil, err
	}
	return &matrix, nil
}
