# === 阶段一：构建 ZeroClaw 可执行文件 ===
# 使用 Rust 官方镜像进行编译（代理环境下正常工作）
FROM rust:1.85-slim-bookworm AS builder

# 设置环境变量：优化编译速度
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true \
    CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

# 安装编译依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev git ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 创建工作目录并克隆官方仓库
WORKDIR /build
RUN git clone --depth 1 --branch v0.75 https://github.com/zeroclaw-labs/zeroclaw.git .

# 编译 release 版本
RUN cargo build --release --locked

# === 阶段二：构建分析沙箱镜像 ===
# 使用 Debian Slim 作为基础镜像
FROM debian:bookworm-slim

LABEL maintainer="security-analyst@example.com"
LABEL description="工业级安全分析沙箱，内置ZeroClaw，用于可疑Skill分析"

# 配置国内镜像源（代理环境可注释掉）
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources && \
    sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources

# 安装分析必需工具（最小化攻击面）
RUN apt-get update && apt-get install -y --no-install-recommends \
    # 基础工具
    curl procps \
    # 网络分析工具
    tcpdump net-tools strace \
    # ZeroClaw 运行时依赖
    ca-certificates libssl3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 创建普通分析用户（禁用密码登录）
RUN useradd -m -s /bin/bash -u 1001 analyst && \
    passwd -l analyst

# 复制编译好的ZeroClaw二进制文件并进行完整性校验
COPY --from=builder /build/target/release/zeroclaw /usr/local/bin/zeroclaw
RUN chmod +x /usr/local/bin/zeroclaw && \
    sha256sum /usr/local/bin/zeroclaw > /zeroclaw.sha256

# 创建ZeroClaw配置目录
RUN mkdir -p /home/analyst/.config/zeroclaw && \
    cp /usr/local/bin/zeroclaw /home/analyst/.config/zeroclaw/zeroclaw.bak && \
    chown -R analyst:analyst /home/analyst/.config

# 删除Docker特征文件
RUN rm -f /.dockerenv 2>/dev/null || true

# 配置启动脚本
COPY --chmod=755 <<'EOF' /entrypoint.sh
#!/bin/bash
set -e

# 验证ZeroClaw二进制文件完整性
if ! sha256sum -c /zeroclaw.sha256; then
    echo "ERROR: ZeroClaw binary has been tampered with!"
    exit 1
fi

# 切换到普通用户
exec su - analyst
EOF

WORKDIR /home/analyst
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]