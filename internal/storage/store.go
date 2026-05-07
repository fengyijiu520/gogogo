package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"skill-scanner/internal/models"
)

// LLMConfig LLM服务的配置，内存中保存解密后的密钥
type LLMConfig struct {
	DeepSeekAPIKey string `json:"deepseek_api_key"`
	MiniMaxGroupID string `json:"minimax_group_id"`
	MiniMaxAPIKey  string `json:"minimax_api_key"`
}

// Store manages user, report, and login-log persistence using JSON files.
// All data is stored relative to the data directory for portability.
type Store struct {
	dataDir string

	users          map[string]*models.User
	reports        []*models.Report
	loginLogs      []*models.LoginLog
	muUsers        sync.RWMutex
	muReports      sync.RWMutex
	muLogs         sync.RWMutex
	muRuleProfiles sync.RWMutex
	llmConfig      *LLMConfig
	muLLMConfig    sync.RWMutex
	feedbackStore  *analyzerFeedbackStore
}

// NewStore creates a new Store under the given data directory.
// The directory is created if it does not exist.
func NewStore(dataDir string) (*Store, error) {
	absDir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Join(absDir, "reports"), 0755); err != nil {
		return nil, err
	}

	s := &Store{dataDir: absDir}
	s.loadUsers()
	s.loadReports()
	s.loadLoginLogs()

	// Ensure default admin account exists for the current development stage.
	s.muUsers.Lock()
	if _, ok := s.users["admin"]; !ok {
		hash, hashErr := HashPassword("admin")
		if hashErr != nil {
			s.muUsers.Unlock()
			return nil, hashErr
		}
		s.users["admin"] = models.NewUser("admin", hash, "", models.RoleAdmin)
		if err := s.saveUsers(); err != nil {
			s.muUsers.Unlock()
			return nil, err
		}
	}
	// Migrate existing users to have a role.
	for _, u := range s.users {
		if u.Role == "" {
			if u.Username == "admin" {
				u.Role = models.RoleAdmin
			} else {
				u.Role = models.RoleMember
			}
		}
	}
	if err := s.saveUsers(); err != nil {
		s.muUsers.Unlock()
		return nil, err
	}
	s.muUsers.Unlock()

	s.loadLLMConfig()
	feedbackStore, err := newAnalyzerFeedbackStore(absDir)
	if err != nil {
		return nil, err
	}
	s.feedbackStore = feedbackStore
	return s, nil
}

func (s *Store) AddAnalyzerFalsePositiveFeedback(ruleID string, token string) error {
	if s == nil || s.feedbackStore == nil {
		return nil
	}
	return s.feedbackStore.Add(ruleID, token)
}

func (s *Store) AnalyzerFalsePositiveFeedback() []AnalyzerFeedbackEntry {
	if s == nil || s.feedbackStore == nil {
		return nil
	}
	return s.feedbackStore.Snapshot()
}

// DataDir returns the absolute path to the data directory.
func (s *Store) DataDir() string {
	return s.dataDir
}

// ReportsDir returns the absolute path to the reports subdirectory.
func (s *Store) ReportsDir() string {
	return filepath.Join(s.dataDir, "reports")
}

// -------- User operations --------

// GetUser retrieves a user by username. Returns nil if not found.
func (s *Store) GetUser(username string) *models.User {
	s.muUsers.RLock()
	defer s.muUsers.RUnlock()
	return s.users[username]
}

// CreateUserWithTeam creates a new member user with a team. Returns error if username already exists.
func (s *Store) CreateUserWithTeam(username, password, team string) error {
	s.muUsers.Lock()
	defer s.muUsers.Unlock()

	if _, exists := s.users[username]; exists {
		return fmt.Errorf("用户名已存在")
	}

	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	s.users[username] = models.NewUser(username, hash, team, models.RoleMember)
	return s.saveUsers()
}

// UpdatePassword changes a user's password.
func (s *Store) UpdatePassword(username, newPassword string) error {
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	s.muUsers.Lock()
	defer s.muUsers.Unlock()

	if _, ok := s.users[username]; !ok {
		return os.ErrNotExist
	}

	s.users[username].PasswordHash = hash
	return s.saveUsers()
}

// DeleteUser removes a user. Admin cannot be deleted.
func (s *Store) DeleteUser(username string) error {
	if username == "admin" {
		return fmt.Errorf("不能删除管理员账号")
	}

	s.muUsers.Lock()
	defer s.muUsers.Unlock()

	if _, ok := s.users[username]; !ok {
		return fmt.Errorf("用户不存在")
	}

	delete(s.users, username)
	return s.saveUsers()
}

// ListUsers returns all non-admin users.
func (s *Store) ListUsers() []*models.User {
	s.muUsers.RLock()
	defer s.muUsers.RUnlock()

	var out []*models.User
	for _, u := range s.users {
		if u.Username == "admin" {
			continue
		}
		out = append(out, u)
	}
	return out
}

// CheckPassword verifies a password against the stored hash.
func (s *Store) CheckPassword(username, password string) bool {
	s.muUsers.RLock()
	user, ok := s.users[username]
	s.muUsers.RUnlock()

	if !ok {
		return false
	}

	return CheckPasswordHash(password, user.PasswordHash) == nil
}

// -------- Login log operations --------

// AppendLoginLog appends a login log entry. It can never be deleted by anyone.
func (s *Store) AppendLoginLog(log *models.LoginLog) error {
	s.muLogs.Lock()
	defer s.muLogs.Unlock()
	s.loginLogs = append(s.loginLogs, log)
	return s.saveLoginLogs()
}

// ListLoginLogs returns all login log entries, newest first.
func (s *Store) ListLoginLogs() []*models.LoginLog {
	s.muLogs.RLock()
	defer s.muLogs.RUnlock()
	out := make([]*models.LoginLog, len(s.loginLogs))
	copy(out, s.loginLogs)
	// Reverse to get newest first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// -------- Report operations --------

// AddReport appends a report to the store.
func (s *Store) AddReport(r *models.Report) error {
	s.muReports.Lock()
	defer s.muReports.Unlock()

	s.reports = append(s.reports, r)
	return s.saveReports()
}

// ListReports returns all reports visible to the given user.
// - Admin sees all reports.
// - Non-admin users see reports from themselves and their team members.
func (s *Store) ListReports(forUsername string) []*models.Report {
	s.muUsers.RLock()
	viewer, viewerOk := s.users[forUsername]
	s.muUsers.RUnlock()

	s.muReports.RLock()
	defer s.muReports.RUnlock()

	// Admin sees everything.
	if viewerOk && viewer.Role == models.RoleAdmin {
		out := make([]*models.Report, len(s.reports))
		copy(out, s.reports)
		return out
	}

	var out []*models.Report
	for _, r := range s.reports {
		if r.Username == forUsername {
			out = append(out, r)
			continue
		}
		// Same team members can see each other's reports.
		if viewerOk && viewer.Team != "" && r.Team == viewer.Team {
			out = append(out, r)
		}
	}
	return out
}

// GetReport retrieves a report by ID.
func (s *Store) GetReport(id string) *models.Report {
	s.muReports.RLock()
	defer s.muReports.RUnlock()

	for _, r := range s.reports {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// CanAccessReport checks whether the given user can access the given report.
func (s *Store) CanAccessReport(username, reportID string) bool {
	rep := s.GetReport(reportID)
	if rep == nil {
		return false
	}

	s.muUsers.RLock()
	user, userOk := s.users[username]
	s.muUsers.RUnlock()

	if !userOk {
		return false
	}

	// Admin can access all.
	if user.Role == models.RoleAdmin {
		return true
	}

	// Owner can always access.
	if rep.Username == username {
		return true
	}

	// Same team members can access.
	if user.Team != "" && user.Team == rep.Team {
		return true
	}

	return false
}

// CanDeleteReport checks whether the given user can delete the given report.
// Admin can delete all reports; non-admin users can only delete their own reports.
func (s *Store) CanDeleteReport(username, reportID string) bool {
	rep := s.GetReport(reportID)
	if rep == nil {
		return false
	}

	s.muUsers.RLock()
	user, userOk := s.users[username]
	s.muUsers.RUnlock()
	if !userOk {
		return false
	}
	if user.Role == models.RoleAdmin {
		return true
	}
	return rep.Username == username
}

// DeleteReport removes the report metadata and best-effort deletes report artifacts.
func (s *Store) DeleteReport(username, reportID string) error {
	if !s.CanDeleteReport(username, reportID) {
		return errors.New("permission denied")
	}

	s.muReports.Lock()
	defer s.muReports.Unlock()

	idx := -1
	var rep *models.Report
	for i, item := range s.reports {
		if item.ID == reportID {
			idx = i
			rep = item
			break
		}
	}
	if idx == -1 || rep == nil {
		return os.ErrNotExist
	}

	targets := uniqueReportPaths(rep)
	for _, rel := range targets {
		if !IsPathSafe(s.ReportsDir(), rel) {
			return fmt.Errorf("unsafe report path: %s", rel)
		}
	}

	s.reports = append(s.reports[:idx], s.reports[idx+1:]...)
	if err := s.saveReports(); err != nil {
		return err
	}

	for _, rel := range targets {
		abs := filepath.Join(s.ReportsDir(), rel)
		if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func uniqueReportPaths(rep *models.Report) []string {
	if rep == nil {
		return nil
	}
	seen := map[string]struct{}{}
	ordered := []string{rep.FilePath, rep.HTMLPath, rep.JSONPath, rep.PDFPath}
	out := make([]string, 0, len(ordered))
	for _, rel := range ordered {
		rel = strings.TrimSpace(rel)
		if rel == "" {
			continue
		}
		if _, ok := seen[rel]; ok {
			continue
		}
		seen[rel] = struct{}{}
		out = append(out, rel)
	}
	return out
}

// -------- Password helpers --------

// HashPassword hashes a password using PBKDF2-HMAC-SHA256 with a random 32-byte salt.
// 100,000 iterations provide strong protection against brute-force attacks.
func HashPassword(password string) (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := pbkdf2Hash(password, salt, 100000)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash), nil
}

// CheckPasswordHash verifies a password against a stored hash.
// Returns nil if the password matches.
func CheckPasswordHash(password, stored string) error {
	parts := strings.SplitN(stored, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid hash format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("invalid salt")
	}
	expectedHash := pbkdf2Hash(password, salt, 100000)
	actualHash, err := hex.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid hash")
	}

	if !constTimeEquals(expectedHash, actualHash) {
		return fmt.Errorf("mismatch")
	}
	return nil
}

func pbkdf2Hash(password string, salt []byte, iterations int) []byte {
	return pbkdf2([]byte(password), salt, iterations, 32)
}

func pbkdf2(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmacSHA256
	hashLen := 32
	totalLen := (keyLen + hashLen - 1) / hashLen * hashLen
	result := make([]byte, totalLen)

	var passwordBytes []byte
	if len(password) > 256 {
		h := sha256.Sum256(password)
		passwordBytes = h[:]
	} else {
		passwordBytes = make([]byte, len(password))
		copy(passwordBytes, password)
	}

	U := make([]byte, hashLen)
	work := make([]byte, hashLen)

	for block := 1; ; block++ {
		blockBytes := append(salt[:],
			byte(block>>24&0xff),
			byte(block>>16&0xff),
			byte(block>>8&0xff),
			byte(block&0xff),
		)
		prf(passwordBytes, blockBytes, U)
		copy(work, U)

		for j := 2; j <= iterations; j++ {
			prf(passwordBytes, U, U)
			for k := 0; k < hashLen; k++ {
				work[k] ^= U[k]
			}
		}

		copy(result[(block-1)*hashLen:], work)
		if block*hashLen >= keyLen {
			break
		}
	}

	return result[:keyLen]
}

func hmacSHA256(key, msg, out []byte) {
	var innerPad [64]byte
	var outerPad [64]byte

	if len(key) > 64 {
		h := sha256.Sum256(key)
		key = h[:]
	}

	for i := 0; i < 64; i++ {
		innerPad[i] = 0x36
		outerPad[i] = 0x5c
	}
	for i := 0; i < len(key); i++ {
		innerPad[i] ^= key[i]
		outerPad[i] ^= key[i]
	}

	inner := sha256.New()
	inner.Write(innerPad[:])
	inner.Write(msg)
	innerSum := inner.Sum(nil)

	outer := sha256.New()
	outer.Write(outerPad[:])
	outer.Write(innerSum)
	outer.Sum(out[:0])
}

func constTimeEquals(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// -------- File I/O --------

func (s *Store) usersPath() string {
	return filepath.Join(s.dataDir, "users.json")
}

func (s *Store) reportsPath() string {
	return filepath.Join(s.dataDir, "reports.json")
}

func (s *Store) loginLogsPath() string {
	return filepath.Join(s.dataDir, "login_logs.json")
}

func (s *Store) secretKeyPath() string {
	return filepath.Join(s.dataDir, "secret.key")
}

func (s *Store) llmConfigPath() string {
	return filepath.Join(s.dataDir, "llm_config.json.enc")
}

func (s *Store) loadUsers() {
	s.muUsers.Lock()
	defer s.muUsers.Unlock()

	s.users = map[string]*models.User{}
	data, err := os.ReadFile(s.usersPath())
	if err != nil {
		return
	}
	json.Unmarshal(data, &s.users)
}

func (s *Store) saveUsers() error {
	data, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.usersPath(), data, 0600)
}

func (s *Store) loadReports() {
	s.muReports.Lock()
	defer s.muReports.Unlock()

	s.reports = []*models.Report{}
	data, err := os.ReadFile(s.reportsPath())
	if err != nil {
		return
	}
	json.Unmarshal(data, &s.reports)
}

func (s *Store) saveReports() error {
	data, err := json.MarshalIndent(s.reports, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.reportsPath(), data, 0600)
}

func (s *Store) loadLoginLogs() {
	s.muLogs.Lock()
	defer s.muLogs.Unlock()

	s.loginLogs = []*models.LoginLog{}
	data, err := os.ReadFile(s.loginLogsPath())
	if err != nil {
		return
	}
	json.Unmarshal(data, &s.loginLogs)
}

func (s *Store) saveLoginLogs() error {
	data, err := json.MarshalIndent(s.loginLogs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.loginLogsPath(), data, 0600)
}

// -------- Path security helpers --------

// IsPathSafe checks whether a relative path stays within the base directory.
func IsPathSafe(base, rel string) bool {
	clean := filepath.Clean(filepath.Join(base, rel))
	absBase, _ := filepath.Abs(base)
	absClean, _ := filepath.Abs(clean)
	return strings.HasPrefix(absClean, absBase)
}

// GenerateID returns a random hex string suitable for unique IDs.
func GenerateID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// getEncryptionKey 获取加密用的AES-256密钥，不存在则生成
func (s *Store) getEncryptionKey() ([]byte, error) {
	keyPath := s.secretKeyPath()
	// 如果密钥文件不存在，生成新的32字节密钥
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		key := make([]byte, 32) // AES-256需要32字节密钥
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		// 保存密钥，权限0600，仅当前用户可读取
		if err := os.WriteFile(keyPath, key, 0600); err != nil {
			return nil, err
		}
		return key, nil
	}
	// 读取已有的密钥
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// encrypt 加密明文数据，返回base64编码的密文
func (s *Store) encrypt(plaintext []byte) (string, error) {
	key, err := s.getEncryptionKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	// 加密，nonce + 密文
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt 解密密文，输入base64编码的密文
func (s *Store) decrypt(ciphertextB64 string) ([]byte, error) {
	key, err := s.getEncryptionKey()
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// loadLLMConfig 加载加密的LLM配置，解密后存入内存
func (s *Store) loadLLMConfig() {
	s.muLLMConfig.Lock()
	defer s.muLLMConfig.Unlock()
	path := s.llmConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		// 文件不存在，配置为空
		s.llmConfig = nil
		return
	}
	// 解密
	plaintext, err := s.decrypt(string(data))
	if err != nil {
		s.llmConfig = nil
		return
	}
	// 反序列化
	var config LLMConfig
	if err := json.Unmarshal(plaintext, &config); err != nil {
		s.llmConfig = nil
		return
	}
	s.llmConfig = &config
}

// saveLLMConfig 保存LLM配置，加密后写入文件
func (s *Store) saveLLMConfig(config *LLMConfig) error {
	// 序列化
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	// 加密
	encrypted, err := s.encrypt(data)
	if err != nil {
		return err
	}
	// 保存到文件
	path := s.llmConfigPath()
	return os.WriteFile(path, []byte(encrypted), 0600)
}

// GetLLMConfig 获取当前的LLM配置，返回副本，密钥会脱敏
func (s *Store) GetLLMConfig() *LLMConfig {
	s.muLLMConfig.RLock()
	defer s.muLLMConfig.RUnlock()
	if s.llmConfig == nil {
		return nil
	}
	// 返回副本，防止外部修改
	cfg := &LLMConfig{
		DeepSeekAPIKey: s.llmConfig.DeepSeekAPIKey,
		MiniMaxGroupID: s.llmConfig.MiniMaxGroupID,
		MiniMaxAPIKey:  s.llmConfig.MiniMaxAPIKey,
	}
	// 脱敏密钥，只显示前4和后4位
	if len(cfg.DeepSeekAPIKey) > 8 {
		cfg.DeepSeekAPIKey = cfg.DeepSeekAPIKey[:4] + "****" + cfg.DeepSeekAPIKey[len(cfg.DeepSeekAPIKey)-4:]
	}
	if len(cfg.MiniMaxAPIKey) > 8 {
		cfg.MiniMaxAPIKey = cfg.MiniMaxAPIKey[:4] + "****" + cfg.MiniMaxAPIKey[len(cfg.MiniMaxAPIKey)-4:]
	}
	return cfg
}

// UpdateLLMConfig 更新LLM配置，加密保存
func (s *Store) UpdateLLMConfig(config *LLMConfig) error {
	if err := s.saveLLMConfig(config); err != nil {
		return err
	}
	s.muLLMConfig.Lock()
	defer s.muLLMConfig.Unlock()
	s.llmConfig = config
	return nil
}

// GetRawLLMConfig 返回未脱敏的 LLM 配置，仅供内部扫描引擎使用
func (s *Store) GetRawLLMConfig() *LLMConfig {
	s.muLLMConfig.RLock()
	defer s.muLLMConfig.RUnlock()
	if s.llmConfig == nil {
		return nil
	}
	// 返回完整副本
	return &LLMConfig{
		DeepSeekAPIKey: s.llmConfig.DeepSeekAPIKey,
		MiniMaxGroupID: s.llmConfig.MiniMaxGroupID,
		MiniMaxAPIKey:  s.llmConfig.MiniMaxAPIKey,
	}
}

// -------- 用户级 LLM 配置（加密存储） --------

// userLLMConfigPath 返回用户 LLM 配置文件的路径
func (s *Store) userLLMConfigPath(username string) string {
	return filepath.Join(s.dataDir, "users_llm", username+".json.enc")
}

// SaveUserLLMConfig 保存用户的 LLM 配置（加密）
func (s *Store) SaveUserLLMConfig(username string, config *models.LLMConfig) error {
	// 确保目录存在
	llmDir := filepath.Join(s.dataDir, "users_llm")
	if err := os.MkdirAll(llmDir, 0700); err != nil {
		return err
	}

	// 复制一份，避免修改原始对象
	cfgCopy := *config
	// 如果 APIKey 不为空，加密存储
	if cfgCopy.APIKey != "" {
		encrypted, err := s.encrypt([]byte(cfgCopy.APIKey))
		if err != nil {
			return err
		}
		cfgCopy.APIKey = encrypted
	}
	// 同样处理 MiniMaxGroupID（可选加密，这里简化处理，明文存储）
	// 如果需要加密 GroupID，可以类似处理，但通常 GroupID 不敏感

	data, err := json.Marshal(&cfgCopy)
	if err != nil {
		return err
	}

	path := s.userLLMConfigPath(username)
	return os.WriteFile(path, data, 0600)
}

// GetUserLLMConfig 读取并解密用户的 LLM 配置
func (s *Store) GetUserLLMConfig(username string) *models.LLMConfig {
	path := s.userLLMConfigPath(username)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // 文件不存在，返回 nil
	}

	var config models.LLMConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil
	}

	// 解密 APIKey
	if config.APIKey != "" {
		plaintext, err := s.decrypt(config.APIKey)
		if err == nil {
			config.APIKey = string(plaintext)
		}
		// 解密失败的话，APIKey 保持原样（可能是旧格式）
	}

	return &config
}

// DeleteUserLLMConfig 删除用户的 LLM 配置文件
func (s *Store) DeleteUserLLMConfig(username string) error {
	path := s.userLLMConfigPath(username)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil // 文件不存在，不算错误
	}
	return os.Remove(path)
}
