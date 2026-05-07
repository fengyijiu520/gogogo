# 使用轻量级的Alpine Linux作为基础镜像
FROM alpine:latest

# 设置镜像维护者信息（可选）
LABEL maintainer="your-email@example.com"
LABEL description="通用技能扫描沙箱镜像，预装Python、Node.js、Go环境"

# 定义环境变量，确保系统使用UTF-8编码
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# 1. 更换Alpine软件源为国内镜像（加速构建）
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

# 2. 安装系统基础工具和三大语言运行时
#    - python3, nodejs, npm, go: 核心运行环境
#    - git, curl, wget: 常用网络工具
#    - make, g++, gcc: 编译工具（用于某些需要编译的Python/Node包）
#    - bash: 更完整的shell环境
RUN apk add --no-cache \
    python3 \
    py3-pip \
    nodejs \
    npm \
    go \
    git \
    curl \
    wget \
    make \
    g++ \
    gcc \
    bash \
    && rm -rf /var/cache/apk/*

# 3. 升级pip（允许突破系统包管理限制，因为我们是在容器内且确有必要）
RUN pip3 install --no-cache-dir --upgrade pip --break-system-packages

# （可选）如果需要安装某些Python包，可以使用--break-system-packages或创建虚拟环境
# 这里我们不预装任何特定Python包，以保持镜像纯净轻量

# 4. 安装全局Node.js工具（可选）
# RUN npm install -g npm-check-updates && npm cache clean --force

# 5. 创建非root用户"sandbox"来运行技能，遵循最小权限原则
RUN addgroup -g 1000 sandbox && \
    adduser -u 1000 -G sandbox -s /bin/bash -D sandbox

# 6. 创建应用目录并设置权限
RUN mkdir -p /app && \
    chown -R sandbox:sandbox /app

# 切换到非root用户
USER sandbox

# 设置工作目录
WORKDIR /app

# 容器启动时的默认命令（可被覆盖）
CMD ["/bin/bash"]