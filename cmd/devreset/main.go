package main

import (
	"fmt"
	"os"
	"path/filepath"

	"skill-scanner/internal/storage"
)

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

	if err := store.UpdatePassword("admin", "admin"); err != nil {
		fmt.Fprintf(os.Stderr, "重置 admin 密码失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("admin 密码已重置为 admin")
}
