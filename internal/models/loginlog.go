package models

import "time"

// LoginResult represents the outcome of a login attempt.
type LoginResult string

const (
	LoginSuccess LoginResult = "success"
	LoginFail    LoginResult = "fail"
)

// LoginLog records a login attempt. It is append-only and cannot be deleted.
type LoginLog struct {
	ID        string      `json:"id"`
	Username  string      `json:"username"`
	Timestamp int64       `json:"timestamp"`
	Result    LoginResult `json:"result"`
	IP        string      `json:"ip"`
}

// NewLoginLog creates a new login log entry.
func NewLoginLog(id, username string, result LoginResult, ip string) *LoginLog {
	return &LoginLog{
		ID:        id,
		Username:  username,
		Timestamp: time.Now().Unix(),
		Result:    result,
		IP:        ip,
	}
}
