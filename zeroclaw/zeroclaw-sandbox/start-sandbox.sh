#!/bin/bash
set -e

# 检查是否提供了待测Skill目录
if [ $# -ne 1 ]; then
    echo "用法: $0 <待测Skill目录路径>"
    echo "示例: $0 ./my-suspicious-skill"
    exit 1
fi

SKILL_DIR=$(realpath "$1")

if [ ! -d "$SKILL_DIR" ]; then
    echo "错误: 目录 $SKILL_DIR 不存在"
    exit 1
fi

# 创建分析网络
docker network create analysis-net > /dev/null 2>&1

echo "🚀 启动ZeroClaw安全分析沙箱"
echo "📂 待测Skill: $SKILL_DIR"
echo "🔒 安全模式: 只读挂载 + 最小权限"
echo "📊 网络监控: 请在另一个终端运行 ./monitor-traffic.sh"
echo ""

# 启动容器
docker run -it --rm \
  --name skill-analysis \
  --network analysis-net \
  --hostname workstation \
  --cpus 4 \
  --memory 4g \
  --memory-swap 4g \
  --pids-limit 200 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=1g \
  --tmpfs /run:rw,noexec,nosuid,size=128m \
  --tmpfs /var/log:rw,noexec,nosuid,size=256m \
  --cap-drop ALL \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --cap-add SYS_PTRACE \
  --security-opt no-new-privileges:true \
  --security-opt apparmor=docker-default \
  --security-opt seccomp=/etc/docker/seccomp/my-seccomp-profile.json \
  -v "$SKILL_DIR:/home/analyst/skill:ro" \
  zeroclaw-sandbox