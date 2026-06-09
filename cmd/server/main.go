package main

import (
	"fmt"
	"os"
	"path/filepath"
	"skill-scanner/internal/config"
	"skill-scanner/internal/handler"
	"skill-scanner/internal/logx"
	"skill-scanner/internal/server"
	"skill-scanner/internal/storage"
)

const bootstrapAdminPasswordEnv = "SKILL_SCANNER_BOOTSTRAP_ADMIN_PASSWORD"

func main() {
	// 初始化日志目录（新日志追加在文件顶部，方便查看最新日志）
	exePath, err := os.Executable()
	if err == nil {
		logDir := filepath.Join(filepath.Dir(exePath), "log")
		logx.SetLogDir(logDir)
	}
	defer logx.Flush()

	handler.InitEmbedder()
	handler.InitRuntimeSelfCheck()
	if len(os.Args) < 2 || os.Args[1] != "web" {
		fmt.Println("用法: skill-scanner web")
		fmt.Println("  启动 Web 登录服务（所有数据存储在 ./data/ 目录下）")
		return
	}

	// Use an absolute path based on the executable's location, so the process
	// can be started from any working directory.
	if exePath == "" {
		fmt.Fprintf(os.Stderr, "获取可执行文件路径失败\n")
		os.Exit(1)
	}
	dataDir := filepath.Join(filepath.Dir(exePath), "data")

	store, err := storage.NewStore(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化存储失败: %v\n", err)
		fmt.Fprintf(os.Stderr, "首次启动请设置环境变量 %s 为至少 12 位的临时管理员密码，登录后立即修改密码。\n", bootstrapAdminPasswordEnv)
		os.Exit(1)
	}

	if err := server.Start(config.ServerListenAddr(), store); err != nil {
		fmt.Fprintf(os.Stderr, "服务器错误: %v\n", err)
		os.Exit(1)
	}
}
