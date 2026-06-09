package storage

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ipv4Re   = regexp.MustCompile(`^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$`)
	ipv6Re   = regexp.MustCompile(`^([\da-fA-F]{1,4}:){7}[\da-fA-F]{1,4}$|^([\da-fA-F]{1,4}:){1,7}:|^::1$|^::$`)
	domainRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

type policyBlacklistStore struct {
	mu sync.RWMutex

	active map[string]map[string]PolicyBlacklistEntry
	draft  map[string]map[string]PolicyBlacklistEntry
	changes []PolicyBlacklistChange

	activePaths map[string]string
	draftPaths  map[string]string
	changePath  string
}

type PolicyBlacklistEntry struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

type PolicyBlacklistChange struct {
	Action    string `json:"action"`
	OldType   string `json:"old_type,omitempty"`
	OldValue  string `json:"old_value,omitempty"`
	NewType   string `json:"new_type,omitempty"`
	NewValue  string `json:"new_value,omitempty"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

func newPolicyBlacklistStore(dataDir string) (*policyBlacklistStore, error) {
	s := &policyBlacklistStore{
		active: map[string]map[string]PolicyBlacklistEntry{"domain": {}, "ipv4": {}, "ipv6": {}},
		draft:  map[string]map[string]PolicyBlacklistEntry{"domain": {}, "ipv4": {}, "ipv6": {}},
		activePaths: map[string]string{
			"domain": filepath.Join(dataDir, "blacklist_domain.json"),
			"ipv4":   filepath.Join(dataDir, "blacklist_ipv4.json"),
			"ipv6":   filepath.Join(dataDir, "blacklist_ipv6.json"),
		},
		draftPaths: map[string]string{
			"domain": filepath.Join(dataDir, "blacklist_domain.draft.json"),
			"ipv4":   filepath.Join(dataDir, "blacklist_ipv4.draft.json"),
			"ipv6":   filepath.Join(dataDir, "blacklist_ipv6.draft.json"),
		},
		changePath: filepath.Join(dataDir, "blacklist_changes.draft.json"),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *policyBlacklistStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range []string{"domain", "ipv4", "ipv6"} {
		activeItems, err := readEntryListFile(s.activePaths[t], t)
		if err != nil {
			return err
		}
		s.active[t] = buildEntryMap(activeItems)

		draftItems, err := readEntryListFile(s.draftPaths[t], t)
		if err != nil {
			return err
		}
		if len(draftItems) == 0 && !fileExists(s.draftPaths[t]) {
			s.draft[t] = cloneEntryMap(s.active[t])
			continue
		}
		s.draft[t] = buildEntryMap(draftItems)
	}
	changes, err := readChangeListFile(s.changePath)
	if err != nil {
		return err
	}
	s.changes = changes
	return s.saveDraftLocked()
}

func (s *policyBlacklistStore) ListActive() []PolicyBlacklistEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return flattenEntries(s.active)
}

func (s *policyBlacklistStore) ListDraft() []PolicyBlacklistEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return flattenEntries(s.draft)
}

func (s *policyBlacklistStore) ListDraftChanges() []PolicyBlacklistChange {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PolicyBlacklistChange, len(s.changes))
	copy(out, s.changes)
	return out
}

func (s *policyBlacklistStore) ListActiveRaw() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0)
	for _, t := range []string{"domain", "ipv4", "ipv6"} {
		for _, item := range s.active[t] {
			out = append(out, item.Value)
		}
	}
	sort.Strings(out)
	return out
}

func (s *policyBlacklistStore) AddDraft(itemType, value string) error {
	t, n, err := normalizeAndValidate(itemType, value)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	if old, ok := s.draft[t][n]; ok {
		old.UpdatedAt = now
		s.draft[t][n] = old
	} else {
		s.draft[t][n] = PolicyBlacklistEntry{Type: t, Value: n, CreatedAt: now, UpdatedAt: now}
	}
	if _, exists := s.active[t][n]; exists {
		s.removeDeleteChange(t, n)
		s.removeModifyChangeByOld(t, n)
	} else {
		s.upsertAddChange(t, n, now)
	}
	return s.saveDraftLocked()
}

func (s *policyBlacklistStore) RemoveDraft(itemType, value string) error {
	t, n, err := normalizeTypeAndValue(itemType, value)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.draft[t], n)
	if _, exists := s.active[t][n]; exists {
		s.upsertDeleteChange(t, n, time.Now().Unix())
	} else {
		s.removeAddChange(t, n)
		s.removeModifyChangeByNew(t, n)
	}
	return s.saveDraftLocked()
}

func (s *policyBlacklistStore) ReplaceDraft(oldType, oldValue, newType, newValue string) error {
	ot, ov, err := normalizeTypeAndValue(oldType, oldValue)
	if err != nil {
		return err
	}
	nt, nv, err := normalizeAndValidate(newType, newValue)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ot == nt && ov == nv {
		return nil
	}
	now := time.Now().Unix()
	delete(s.draft[ot], ov)
	createdAt := now
	if old, ok := s.draft[ot][ov]; ok && old.CreatedAt > 0 {
		createdAt = old.CreatedAt
	}
	if activeOld, ok := s.active[ot][ov]; ok && activeOld.CreatedAt > 0 {
		createdAt = activeOld.CreatedAt
	}
	s.draft[nt][nv] = PolicyBlacklistEntry{Type: nt, Value: nv, CreatedAt: createdAt, UpdatedAt: now}
	if _, exists := s.active[ot][ov]; exists {
		if ot == nt && ov == nv {
			s.removeModifyChangeByOld(ot, ov)
		} else {
			s.removeDeleteChange(ot, ov)
			s.removeAddChange(nt, nv)
			s.upsertModifyChange(ot, ov, nt, nv, now)
		}
	} else {
		if idx := s.findAddChange(ot, ov); idx >= 0 {
			s.changes[idx].NewType = nt
			s.changes[idx].NewValue = nv
			s.changes[idx].UpdatedAt = now
		} else if idx := s.findModifyChangeByNew(ot, ov); idx >= 0 {
			s.changes[idx].NewType = nt
			s.changes[idx].NewValue = nv
			s.changes[idx].UpdatedAt = now
		} else {
			s.upsertAddChange(nt, nv, now)
		}
	}
	return s.saveDraftLocked()
}

func (s *policyBlacklistStore) SaveDraftAsActive() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = map[string]map[string]PolicyBlacklistEntry{
		"domain": cloneEntryMap(s.draft["domain"]),
		"ipv4":   cloneEntryMap(s.draft["ipv4"]),
		"ipv6":   cloneEntryMap(s.draft["ipv6"]),
	}
	s.changes = nil
	if err := s.saveActiveLocked(); err != nil {
		return err
	}
	return nil
}

func (s *policyBlacklistStore) DiscardDraft() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.draft = map[string]map[string]PolicyBlacklistEntry{
		"domain": cloneEntryMap(s.active["domain"]),
		"ipv4":   cloneEntryMap(s.active["ipv4"]),
		"ipv6":   cloneEntryMap(s.active["ipv6"]),
	}
	s.changes = nil
	return s.saveDraftLocked()
}

func (s *policyBlacklistStore) IsDraftDirty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range []string{"domain", "ipv4", "ipv6"} {
		if len(s.active[t]) != len(s.draft[t]) {
			return true
		}
		for k := range s.active[t] {
			if _, ok := s.draft[t][k]; !ok {
				return true
			}
		}
	}
	return false
}

func (s *policyBlacklistStore) saveActiveLocked() error {
	for _, t := range []string{"domain", "ipv4", "ipv6"} {
		if err := writeEntryListFile(s.activePaths[t], entryList(s.active[t])); err != nil {
			return err
		}
	}
	return nil
}

func (s *policyBlacklistStore) saveDraftLocked() error {
	for _, t := range []string{"domain", "ipv4", "ipv6"} {
		if err := writeEntryListFile(s.draftPaths[t], entryList(s.draft[t])); err != nil {
			return err
		}
	}
	if err := writeChangeListFile(s.changePath, s.changes); err != nil {
		return err
	}
	return nil
}

func readChangeListFile(path string) ([]PolicyBlacklistChange, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var out []PolicyBlacklistChange
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func writeChangeListFile(path string, items []PolicyBlacklistChange) error {
	body, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0600)
}

func readEntryListFile(path string, itemType string) ([]PolicyBlacklistEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []PolicyBlacklistEntry{}, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return []PolicyBlacklistEntry{}, nil
	}

	var values []string
	if err := json.Unmarshal(data, &values); err == nil {
		return buildLegacyEntries(itemType, values), nil
	}

	var entries []PolicyBlacklistEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return normalizeLoadedEntries(itemType, entries), nil
}

func writeEntryListFile(path string, items []PolicyBlacklistEntry) error {
	body, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0600)
}

func buildEntryMap(items []PolicyBlacklistEntry) map[string]PolicyBlacklistEntry {
	out := make(map[string]PolicyBlacklistEntry)
	for _, item := range items {
		t, n, err := normalizeAndValidate(item.Type, item.Value)
		if err != nil {
			continue
		}
		if item.CreatedAt <= 0 {
			item.CreatedAt = time.Now().Unix()
		}
		if item.UpdatedAt <= 0 {
			item.UpdatedAt = item.CreatedAt
		}
		out[n] = PolicyBlacklistEntry{Type: t, Value: n, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
	}
	return out
}

func buildLegacyEntries(itemType string, values []string) []PolicyBlacklistEntry {
	now := time.Now().Unix()
	entries := make([]PolicyBlacklistEntry, 0, len(values))
	for _, value := range values {
		t, n, err := normalizeAndValidate(itemType, value)
		if err != nil {
			continue
		}
		entries = append(entries, PolicyBlacklistEntry{Type: t, Value: n, CreatedAt: now, UpdatedAt: now})
	}
	return entries
}

func normalizeLoadedEntries(itemType string, entries []PolicyBlacklistEntry) []PolicyBlacklistEntry {
	out := make([]PolicyBlacklistEntry, 0, len(entries))
	now := time.Now().Unix()
	for _, entry := range entries {
		if strings.TrimSpace(entry.Type) == "" {
			entry.Type = itemType
		}
		t, n, err := normalizeAndValidate(entry.Type, entry.Value)
		if err != nil {
			continue
		}
		entry.Type = t
		entry.Value = n
		if entry.CreatedAt <= 0 {
			entry.CreatedAt = now
		}
		if entry.UpdatedAt <= 0 {
			entry.UpdatedAt = entry.CreatedAt
		}
		out = append(out, entry)
	}
	return out
}

func normalizeAndValidate(itemType, value string) (string, string, error) {
	t, n, err := normalizeTypeAndValue(itemType, value)
	if err != nil {
		return "", "", err
	}
	if err := validateBlacklistValue(t, n); err != nil {
		return "", "", err
	}
	return t, n, nil
}

func normalizeTypeAndValue(itemType, value string) (string, string, error) {
	t := normalizeBlacklistType(itemType)
	n := strings.TrimSpace(value)
	if t == "" || n == "" {
		return "", "", fmt.Errorf("黑名单类型或内容不能为空")
	}
	if t == "domain" || t == "ipv6" {
		n = strings.ToLower(n)
	}
	return t, n, nil
}

func normalizeBlacklistType(itemType string) string {
	t := strings.ToLower(strings.TrimSpace(itemType))
	switch t {
	case "domain", "ipv4", "ipv6":
		return t
	case "ip":
		return "ipv4"
	default:
		return ""
	}
}

func validateBlacklistValue(itemType, value string) error {
	if strings.Contains(value, "/") {
		ip, _, err := net.ParseCIDR(value)
		if err != nil {
			return fmt.Errorf("CIDR 格式无效")
		}
		if itemType == "ipv4" && ip.To4() == nil {
			return fmt.Errorf("CIDR 必须是 IPv4 段")
		}
		if itemType == "ipv6" && ip.To4() != nil {
			return fmt.Errorf("CIDR 必须是 IPv6 段")
		}
		return nil
	}
	switch itemType {
	case "domain":
		if !domainRe.MatchString(value) {
			return fmt.Errorf("域名格式无效")
		}
	case "ipv4":
		if !ipv4Re.MatchString(value) {
			return fmt.Errorf("IPv4 格式无效")
		}
	case "ipv6":
		if !ipv6Re.MatchString(value) {
			return fmt.Errorf("IPv6 格式无效")
		}
	default:
		return fmt.Errorf("不支持的黑名单类型")
	}
	return nil
}

func flattenEntries(groups map[string]map[string]PolicyBlacklistEntry) []PolicyBlacklistEntry {
	out := make([]PolicyBlacklistEntry, 0)
	for _, t := range []string{"domain", "ipv4", "ipv6"} {
		for _, item := range groups[t] {
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type == out[j].Type {
			return out[i].Value < out[j].Value
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func entryList(items map[string]PolicyBlacklistEntry) []PolicyBlacklistEntry {
	out := make([]PolicyBlacklistEntry, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt == out[j].CreatedAt {
			return out[i].Value < out[j].Value
		}
		return out[i].CreatedAt > out[j].CreatedAt
	})
	return out
}

func cloneEntryMap(src map[string]PolicyBlacklistEntry) map[string]PolicyBlacklistEntry {
	out := make(map[string]PolicyBlacklistEntry, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func (s *policyBlacklistStore) findAddChange(itemType, value string) int {
	for i, change := range s.changes {
		if change.Action == "add" && change.NewType == itemType && change.NewValue == value {
			return i
		}
	}
	return -1
}

func (s *policyBlacklistStore) findDeleteChange(itemType, value string) int {
	for i, change := range s.changes {
		if change.Action == "delete" && change.OldType == itemType && change.OldValue == value {
			return i
		}
	}
	return -1
}

func (s *policyBlacklistStore) findModifyChangeByOld(itemType, value string) int {
	for i, change := range s.changes {
		if change.Action == "modify" && change.OldType == itemType && change.OldValue == value {
			return i
		}
	}
	return -1
}

func (s *policyBlacklistStore) findModifyChangeByNew(itemType, value string) int {
	for i, change := range s.changes {
		if change.Action == "modify" && change.NewType == itemType && change.NewValue == value {
			return i
		}
	}
	return -1
}

func (s *policyBlacklistStore) removeChangeAt(idx int) {
	if idx < 0 || idx >= len(s.changes) {
		return
	}
	s.changes = append(s.changes[:idx], s.changes[idx+1:]...)
}

func (s *policyBlacklistStore) upsertAddChange(itemType, value string, now int64) {
	if idx := s.findAddChange(itemType, value); idx >= 0 {
		s.changes[idx].UpdatedAt = now
		return
	}
	s.changes = append(s.changes, PolicyBlacklistChange{Action: "add", NewType: itemType, NewValue: value, CreatedAt: now, UpdatedAt: now})
}

func (s *policyBlacklistStore) upsertDeleteChange(itemType, value string, now int64) {
	if idx := s.findDeleteChange(itemType, value); idx >= 0 {
		s.changes[idx].UpdatedAt = now
		return
	}
	s.changes = append(s.changes, PolicyBlacklistChange{Action: "delete", OldType: itemType, OldValue: value, CreatedAt: now, UpdatedAt: now})
}

func (s *policyBlacklistStore) upsertModifyChange(oldType, oldValue, newType, newValue string, now int64) {
	if idx := s.findModifyChangeByOld(oldType, oldValue); idx >= 0 {
		s.changes[idx].NewType = newType
		s.changes[idx].NewValue = newValue
		s.changes[idx].UpdatedAt = now
		return
	}
	s.changes = append(s.changes, PolicyBlacklistChange{Action: "modify", OldType: oldType, OldValue: oldValue, NewType: newType, NewValue: newValue, CreatedAt: now, UpdatedAt: now})
}

func (s *policyBlacklistStore) removeAddChange(itemType, value string) {
	s.removeChangeAt(s.findAddChange(itemType, value))
}

func (s *policyBlacklistStore) removeDeleteChange(itemType, value string) {
	s.removeChangeAt(s.findDeleteChange(itemType, value))
}

func (s *policyBlacklistStore) removeModifyChangeByOld(itemType, value string) {
	s.removeChangeAt(s.findModifyChangeByOld(itemType, value))
}

func (s *policyBlacklistStore) removeModifyChangeByNew(itemType, value string) {
	s.removeChangeAt(s.findModifyChangeByNew(itemType, value))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
