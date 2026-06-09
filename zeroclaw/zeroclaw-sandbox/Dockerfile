# === 阶段一：构建 ZeroClaw 可执行文件 ===
# 使用 Rust 官方镜像进行编译（代理环境下正常工作）
FROM rust:1.88-slim-bookworm AS builder

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
RUN git clone --depth 1 --branch v0.7.5 https://github.com/zeroclaw-labs/zeroclaw.git .

# 编译 release 版本
RUN cargo build --release

# === 阶段二：构建分析沙箱镜像 ===
# 使用 Debian Slim 作为基础镜像
FROM debian:bookworm-slim

LABEL maintainer="security-analyst@example.com"
LABEL description="工业级安全分析沙箱，内置ZeroClaw，用于可疑Skill分析"

# 配置国内镜像源（代理环境可注释掉）
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources && \
    sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources

# 安装基础工具、网络分析工具和系统服务
RUN apt-get update && apt-get install -y --no-install-recommends \
    # 基础工具
    curl wget git vim htop procps \
    # 网络分析工具
    tcpdump net-tools lsof strace iptables \
    # 进程追踪工具
    strace \
    # 系统服务（用于伪装和诱饵）
    openssh-server nginx \
    # ZeroClaw 运行时依赖
    ca-certificates libssl3 \
    # 进程管理
    supervisor \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 配置SSH服务（仅监听本地回环，作为诱饵，带暴力破解防护）
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config && \
    sed -i 's/#ListenAddress 0.0.0.0/ListenAddress 127.0.0.1/g' /etc/ssh/sshd_config && \
    sed -i 's/#MaxAuthTries 6/MaxAuthTries 2/g' /etc/ssh/sshd_config && \
    sed -i 's/#MaxSessions 10/MaxSessions 2/g' /etc/ssh/sshd_config && \
    sed -i 's/#LoginGraceTime 2m/LoginGraceTime 10s/g' /etc/ssh/sshd_config && \
    ssh-keygen -A

# 创建普通分析用户（禁用密码登录）
RUN useradd -m -s /bin/bash -u 1001 analyst && \
    passwd -l analyst

# 伪造用户操作历史和目录结构
RUN echo "ls -la" >> /home/analyst/.bash_history && \
    echo "cd /var/log" >> /home/analyst/.bash_history && \
    echo "git clone https://github.com/redis/redis.git" >> /home/analyst/.bash_history && \
    echo "python3 script.py" >> /home/analyst/.bash_history && \
    echo "sudo apt-get update" >> /home/analyst/.bash_history && \
    mkdir -p /home/analyst/.ssh /home/analyst/Documents /home/analyst/Downloads /home/analyst/Pictures && \
    chmod 700 /home/analyst/.ssh && \
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD... analyst@workstation" > /home/analyst/.ssh/authorized_keys && \
    echo "Confidential Report - Do Not Distribute" > /home/analyst/Documents/report.txt && \
    touch /home/analyst/Downloads/installer.exe /home/analyst/Downloads/data.zip && \
    chown -R analyst:analyst /home/analyst

# 创建Nginx默认页面
RUN mkdir -p /var/www/html && \
    echo "<!DOCTYPE html>" > /var/www/html/index.html && \
    echo "<html><head><title>Company Intranet</title></head>" >> /var/www/html/index.html && \
    echo "<body><h1>Welcome to Company Intranet</h1><p>Please log in to access resources.</p></body></html>" >> /var/www/html/index.html

# 配置Supervisor管理后台服务
RUN mkdir -p /var/log/supervisor
COPY --chmod=644 <<EOF /etc/supervisor/conf.d/services.conf
[program:sshd]
command=/usr/sbin/sshd -D
autostart=true
autorestart=true
startretries=3

[program:nginx]
command=/usr/sbin/nginx -g "daemon off;"
autostart=true
autorestart=true
startretries=3
EOF

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

# 再次删除Docker特征文件
rm -f /.dockerenv 2>/dev/null

# 增强cgroup和mountinfo伪装
if [ -f /proc/self/cgroup ]; then
    sed -i 's/docker/init/g' /proc/self/cgroup 2>/dev/null
    sed -i 's/containerd/systemd/g' /proc/self/cgroup 2>/dev/null
fi

if [ -f /proc/self/mountinfo ]; then
    sed -i 's/docker/overlay/g' /proc/self/mountinfo 2>/dev/null
fi

# 可选：启动假进程增强伪装（取消注释启用）
# for i in {1..10}; do
#     sleep 3600 &
# done

# 启动Supervisor
/usr/bin/supervisord -c /etc/supervisor/supervisord.conf &

# 等待服务就绪
until curl -s http://localhost:80 > /dev/null; do
    sleep 1
done

# 切换到普通用户
exec su - analyst
EOF

WORKDIR /home/analyst
EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]