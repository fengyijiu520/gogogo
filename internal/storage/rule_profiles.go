package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"skill-scanner/internal/models"
)

func (s *Store) ruleProfilesPath(username string) string {
	return filepath.Join(s.dataDir, "users_rule_profiles", username+".json")
}

func (s *Store) ListUserRuleProfiles(username string) []models.RuleProfile {
	s.muRuleProfiles.RLock()
	defer s.muRuleProfiles.RUnlock()

	profiles, _ := s.loadUserRuleProfilesUnlocked(username)
	return profiles
}

func (s *Store) SaveUserRuleProfile(username string, in models.RuleProfile) error {
	s.muRuleProfiles.Lock()
	defer s.muRuleProfiles.Unlock()

	name := strings.TrimSpace(in.Name)
	if name == "" {
		return os.ErrInvalid
	}

	profiles, path := s.loadUserRuleProfilesUnlocked(username)
	now := time.Now().Unix()
	updated := false
	for i := range profiles {
		if strings.EqualFold(strings.TrimSpace(profiles[i].Name), name) {
			in.CreatedAt = profiles[i].CreatedAt
			in.UpdatedAt = now
			profiles[i] = in
			updated = true
			break
		}
	}
	if !updated {
		in.CreatedAt = now
		in.UpdatedAt = now
		profiles = append(profiles, in)
	}

	return s.writeRuleProfilesUnlocked(path, profiles)
}

func (s *Store) RenameUserRuleProfile(username, oldName, newName string) error {
	s.muRuleProfiles.Lock()
	defer s.muRuleProfiles.Unlock()

	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if oldName == "" || newName == "" {
		return os.ErrInvalid
	}

	profiles, path := s.loadUserRuleProfilesUnlocked(username)
	if len(profiles) == 0 {
		return fmt.Errorf("配置不存在")
	}

	for i := range profiles {
		if strings.EqualFold(strings.TrimSpace(profiles[i].Name), newName) && !strings.EqualFold(strings.TrimSpace(profiles[i].Name), oldName) {
			return fmt.Errorf("配置名称已存在")
		}
	}

	found := false
	now := time.Now().Unix()
	for i := range profiles {
		if strings.EqualFold(strings.TrimSpace(profiles[i].Name), oldName) {
			profiles[i].Name = newName
			profiles[i].UpdatedAt = now
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("配置不存在")
	}

	return s.writeRuleProfilesUnlocked(path, profiles)
}

func (s *Store) DeleteUserRuleProfile(username, name string) error {
	s.muRuleProfiles.Lock()
	defer s.muRuleProfiles.Unlock()

	name = strings.TrimSpace(name)
	if name == "" {
		return os.ErrInvalid
	}

	profiles, path := s.loadUserRuleProfilesUnlocked(username)
	if len(profiles) == 0 {
		return fmt.Errorf("配置不存在")
	}

	filtered := make([]models.RuleProfile, 0, len(profiles))
	found := false
	for _, p := range profiles {
		if strings.EqualFold(strings.TrimSpace(p.Name), name) {
			found = true
			continue
		}
		filtered = append(filtered, p)
	}
	if !found {
		return fmt.Errorf("配置不存在")
	}

	return s.writeRuleProfilesUnlocked(path, filtered)
}

func (s *Store) loadUserRuleProfilesUnlocked(username string) ([]models.RuleProfile, string) {
	path := s.ruleProfilesPath(username)
	profiles := make([]models.RuleProfile, 0)
	data, err := os.ReadFile(path)
	if err != nil {
		return profiles, path
	}
	_ = json.Unmarshal(data, &profiles)
	return profiles, path
}

func (s *Store) writeRuleProfilesUnlocked(path string, profiles []models.RuleProfile) error {
	dir := filepath.Join(s.dataDir, "users_rule_profiles")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
