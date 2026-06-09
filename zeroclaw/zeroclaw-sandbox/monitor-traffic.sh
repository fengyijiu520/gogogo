#!/bin/bash
set -e

# 创建分析网络（如果不存在）
docker network create analysis-net > /dev/null 2>&1

# 可靠获取桥接接口名
BRIDGE_NAME=$(docker network inspect analysis-net -f '{{index .Options "com.docker.network.bridge.name"}}')

# 如果未获取到，使用备用方法
if [ -z "$BRIDGE_NAME" ]; then
    NETWORK_ID=$(docker network inspect analysis-net -f '{{.Id}}')
    BRIDGE_NAME="br-${NETWORK_ID:0:12}"
fi

echo "✅ 网络监控已启动"
echo "📡 监控接口：$BRIDGE_NAME"
echo "💾 流量保存到：analysis-$(date +%Y%m%d-%H%M%S).pcap"
echo "⏹️  按 Ctrl+C 停止监控"
echo ""

# 启动tcpdump抓包，每个文件100MB，最多保留10个文件
sudo tcpdump -i "$BRIDGE_NAME" -w "analysis-$(date +%Y%m%d-%H%M%S).pcap" -n -C 100 -W 10