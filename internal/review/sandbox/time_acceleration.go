package sandbox

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"skill-scanner/internal/logx"
)

// timeAccelerator 沙箱时间加速器
// 通过 libfaketime + LD_PRELOAD 实现容器内时间加速
type timeAccelerator struct {
	enabled   bool
	multiplier int  // 加速倍数（如 10 表示 1秒现实=10秒沙箱）
	startTime string // 伪造的起始时间
}

// newTimeAccelerator 创建时间加速器
func newTimeAccelerator() *timeAccelerator {
	enabled := readEnvOrDefault("REVIEW_SANDBOX_TIME_ACCELERATION", "") != ""
	multiplier := readPositiveIntEnv("REVIEW_SANDBOX_TIME_MULTIPLIER", 1)
	if multiplier < 1 {
		multiplier = 1
	}
	if multiplier > 100 {
		multiplier = 100
	}

	return &timeAccelerator{
		enabled:    enabled,
		multiplier: multiplier,
		startTime:  readEnvOrDefault("REVIEW_SANDBOX_TIME_START", ""),
	}
}

// injectTimeAcceleration 注入时间加速到容器
func (t *timeAccelerator) injectTimeAcceleration(ctx context.Context, containerName string) error {
	if !t.enabled || t.multiplier <= 1 {
		return nil
	}

	logger := logx.With("component", "time_accelerator", "container", containerName, "multiplier", t.multiplier)

	// 检查容器内是否有 libfaketime
	checkCmd := exec.CommandContext(ctx, "docker", "exec", containerName,
		"/bin/bash", "-c", "ls /usr/lib/*/faketime/libfaketime.so* 2>/dev/null || ls /usr/lib/faketime/libfaketime.so* 2>/dev/null")
	out, _ := checkCmd.CombinedOutput()
	faketimePath := strings.TrimSpace(string(out))

	if faketimePath == "" {
		// 安装 libfaketime
		logger.Info("installing libfaketime")
		installCmd := exec.CommandContext(ctx, "docker", "exec", containerName,
			"/bin/bash", "-c", "apt-get update -qq && apt-get install -y -qq libfaketime 2>/dev/null")
		if err := installCmd.Run(); err != nil {
			logger.Warn("failed to install libfaketime", "error", err.Error())
			return fmt.Errorf("安装 libfaketime 失败: %w", err)
		}
		faketimePath = "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1"
	}

	// 构造 faketime 环境变量
	faketimeStr := fmt.Sprintf("+0 x%d", t.multiplier)
	if t.startTime != "" {
		faketimeStr = fmt.Sprintf("%s x%d", t.startTime, t.multiplier)
	}

	// 写入环境变量到容器
	envSetup := fmt.Sprintf("echo 'export LD_PRELOAD=%s' >> /home/analyst/.bashrc && echo 'export FAKETIME=%s' >> /home/analyst/.bashrc",
		faketimePath, faketimeStr)
	envCmd := exec.CommandContext(ctx, "docker", "exec", containerName,
		"/bin/bash", "-c", envSetup)
	if err := envCmd.Run(); err != nil {
		logger.Warn("failed to inject time acceleration", "error", err.Error())
		return err
	}

	logger.Info("time acceleration injected", "faketime", faketimeStr, "lib", faketimePath)
	return nil
}

// getTimeAccelerationEnv 获取时间加速环境变量（用于 docker exec）
func (t *timeAccelerator) getTimeAccelerationEnv() []string {
	if !t.enabled || t.multiplier <= 1 {
		return nil
	}

	faketimeStr := fmt.Sprintf("+0 x%d", t.multiplier)
	if t.startTime != "" {
		faketimeStr = fmt.Sprintf("%s x%d", t.startTime, t.multiplier)
	}

	return []string{
		"LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
		"FAKETIME=" + faketimeStr,
	}
}
