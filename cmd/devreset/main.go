package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"skill-scanner/internal/storage"
)

const resetAdminPasswordEnv = "SKILL_SCANNER_RESET_ADMIN_PASSWORD"

func main() {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "获取可执行文件路径失败: %v\n", err)
		os.Exit(1)
	}

	dataDir := filepath.Join(filepath.Dir(exePath), "data")
	store, err := storage.NewStore(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化存储失败: %v\n", err)
		os.Exit(1)
	}

	newPassword := strings.TrimSpace(os.Getenv(resetAdminPasswordEnv))
	if len(newPassword) < 12 {
		fmt.Fprintf(os.Stderr, "请设置环境变量 %s 为至少 12 位的新 admin 密码。\n", resetAdminPasswordEnv)
		os.Exit(1)
	}

	if err := store.UpdatePassword("admin", newPassword); err != nil {
		fmt.Fprintf(os.Stderr, "重置 admin 密码失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("admin 密码已重置，请使用新密码登录后妥善保管。")
}
