package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	once     sync.Once
	base     *slog.Logger
	logFile  *os.File
	logPath  string
	logMu    sync.Mutex
)

const RequestIDContextKey = "request_id"

// SetLogDir 设置日志目录，启用文件日志（新日志追加在文件顶部）
func SetLogDir(dir string) {
	logMu.Lock()
	defer logMu.Unlock()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "logx: 创建日志目录失败: %v\n", err)
		return
	}
	logPath = filepath.Join(dir, "skill-scanner.log")
}

func L() *slog.Logger {
	once.Do(initLogger)
	return base
}

func With(args ...any) *slog.Logger {
	return L().With(args...)
}

func FromContext(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return L()
	}
	if rid, ok := ctx.Value(RequestIDContextKey).(string); ok && strings.TrimSpace(rid) != "" {
		return L().With("request_id", strings.TrimSpace(rid))
	}
	return L()
}

func initLogger() {
	level := parseLevel(os.Getenv("LOG_LEVEL"))
	// 默认 debug 级别（测试阶段）
	if os.Getenv("LOG_LEVEL") == "" {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}

	// 多路输出：stdout + 文件
	writers := []any{os.Stdout}

	// 如果设置了日志目录，启用文件日志
	if logPath != "" {
		// 读取已有日志内容
		oldContent, _ := os.ReadFile(logPath)

		// 创建/截断日志文件（新日志写在前面）
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "logx: 打开日志文件失败: %v\n", err)
		} else {
			logFile = f
			// 写入会话头
			header := fmt.Sprintf("=== 新会话开始 %s ===\n", time.Now().Format("2006-01-02 15:04:05"))
			f.WriteString(header)

			// 注册关闭钩子：会话结束时追加旧日志
			atExit := func() {
				if len(oldContent) > 0 {
					f.WriteString("\n=== 以下是之前的日志 ===\n")
					f.Write(oldContent)
				}
				f.Close()
			}
			// 用 finalizer 或全局 cleanup（简化：直接在 init 中注册）
			registerCleanup(atExit)

			writers = append(writers, f)
		}
	}

	// 创建多路 handler（同时写入 stdout 和文件）
	textMode := strings.ToLower(strings.TrimSpace(os.Getenv("LOG_FORMAT"))) == "text"
	ioWriters := make([]io.Writer, 0, len(writers))
	for _, w := range writers {
		if iw, ok := w.(io.Writer); ok {
			ioWriters = append(ioWriters, iw)
		}
	}
	base = slog.New(newMultiWriterHandler(ioWriters, opts, textMode))
}

// cleanup 注册程序退出时的清理函数
var cleanupFuncs []func()

func registerCleanup(fn func()) {
	cleanupFuncs = append(cleanupFuncs, fn)
}

// Flush 在程序退出前调用，刷新日志
func Flush() {
	logMu.Lock()
	defer logMu.Unlock()
	for _, fn := range cleanupFuncs {
		fn()
	}
	cleanupFuncs = nil
}

func parseLevel(v string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
