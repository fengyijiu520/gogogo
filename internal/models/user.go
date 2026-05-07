package models

import "time"

// Role defines a user's permission level.
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

// Permission represents an individual feature permission.
type Permission string

const (
	PermPersonalCenter Permission = "personal_center"
	PermUserManagement  Permission = "user_management"
	PermLoginLog        Permission = "login_log"
	PermScan            Permission = "scan"
	PermReports         Permission = "reports"
)

// RolePermissions maps each role to its allowed permissions.
var RolePermissions = map[Role][]Permission{
	RoleAdmin:  {PermPersonalCenter, PermUserManagement, PermLoginLog, PermScan, PermReports},
	RoleMember: {PermPersonalCenter, PermScan, PermReports},
}

// User represents a registered user account.
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"` // PBKDF2-HMAC-SHA256 hash
	Team         string `json:"team"`           // team name, empty means no team
	Role         Role   `json:"role"`           // admin or member
	CreatedAt    int64  `json:"created_at"`
	LLMConfig    *LLMConfig `json:"llm_config,omitempty"` // 新增这一行
}

// NewUser creates a new user with the given credentials, team, and role.
func NewUser(username, passwordHash, team string, role Role) *User {
	return &User{
		Username:     username,
		PasswordHash: passwordHash,
		Team:         team,
		Role:         role,
		CreatedAt:    time.Now().Unix(),
	}
}

// HasPermission checks whether the user has the given permission.
func (u *User) HasPermission(perm Permission) bool {
	perms, ok := RolePermissions[u.Role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

// LLMConfig 用户个人的大模型配置（加密存储）
type LLMConfig struct {
	Enabled        bool   `json:"enabled"`                   // 是否启用LLM分析
	Provider       string `json:"provider,omitempty"`        // "deepseek" 或 "minimax"
	APIKey         string `json:"api_key,omitempty"`         // API密钥（加密后的）
	MiniMaxGroupID string `json:"minimax_group_id,omitempty"` // MiniMax专用GroupID
}