#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

REQUIRED_GO="1.25.0"

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

version_ge() {
  [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

require_root_for_apt() {
  if [ "$(id -u)" -ne 0 ]; then
    cat <<'EOF'
[错误] 检测到需要通过 apt 安装缺失依赖，但当前不是 root 用户。
请使用 root 用户重新执行：
  ./scripts/setup_env.sh
EOF
    exit 1
  fi
}

install_apt_packages_if_missing() {
  if ! command_exists apt-get; then
    echo "[提示] 未检测到 apt-get，跳过系统包自动安装，请手动安装依赖。"
    return 0
  fi

  local missing=()
  local tools=(git curl tar xz)
  local pkgs=(git curl ca-certificates tar xz-utils)
  local idx

  for idx in "${!tools[@]}"; do
    if ! command_exists "${tools[$idx]}"; then
      missing+=("${pkgs[$idx]}")
    fi
  done

  if ! command_exists docker; then
    missing+=("docker.io")
  fi

  if ! command_exists soffice && ! command_exists libreoffice; then
    missing+=("libreoffice")
  fi

  if command_exists fc-list; then
    if ! fc-list | grep -qi "Noto Sans CJK"; then
      missing+=("fonts-noto-cjk")
    fi
  else
    missing+=("fontconfig" "fonts-noto-cjk")
  fi

  if [ ${#missing[@]} -eq 0 ]; then
    echo "[1/6] 系统依赖已满足"
    return 0
  fi

  require_root_for_apt

  echo "[1/6] 安装缺失系统依赖: ${missing[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}

install_or_upgrade_go_if_needed() {
  local need_install=true
  local current=""

  if command_exists go; then
    current="$(go version | awk '{print $3}' | sed 's/^go//')"
    if version_ge "$current" "$REQUIRED_GO"; then
      need_install=false
      echo "[2/6] Go 版本满足要求: $current"
    fi
  fi

  if [ "$need_install" = false ]; then
    return 0
  fi

  local uname_s uname_m go_arch
  uname_s="$(uname -s)"
  uname_m="$(uname -m)"

  if [ "$uname_s" != "Linux" ]; then
    echo "[错误] 自动安装 Go 仅支持 Linux，请手动安装 Go >= ${REQUIRED_GO}"
    exit 1
  fi

  case "$uname_m" in
    x86_64|amd64) go_arch="amd64" ;;
    aarch64|arm64) go_arch="arm64" ;;
    *)
      echo "[错误] 不支持的架构: $uname_m，请手动安装 Go >= ${REQUIRED_GO}"
      exit 1
      ;;
  esac

  local go_dir tarball_url tarball_path
  go_dir="$HOME/.local/go-${REQUIRED_GO}"
  tarball_url="https://go.dev/dl/go${REQUIRED_GO}.linux-${go_arch}.tar.gz"
  tarball_path="/tmp/go${REQUIRED_GO}.linux-${go_arch}.tar.gz"

  echo "[2/6] 安装 Go ${REQUIRED_GO} 到 ${go_dir}"
  mkdir -p "$go_dir"
  curl -fsSL "$tarball_url" -o "$tarball_path"
  tar -xzf "$tarball_path" -C "$go_dir" --strip-components=1
  export PATH="$go_dir/bin:$PATH"

  local path_line
  path_line='export PATH="$HOME/.local/go-1.25.0/bin:$PATH"'
  if [ -f "$HOME/.bashrc" ] && ! grep -Fq "$path_line" "$HOME/.bashrc"; then
    printf '\n%s\n' "$path_line" >> "$HOME/.bashrc"
  fi
  if [ -f "$HOME/.zshrc" ] && ! grep -Fq "$path_line" "$HOME/.zshrc"; then
    printf '\n%s\n' "$path_line" >> "$HOME/.zshrc"
  fi

  current="$(go version | awk '{print $3}' | sed 's/^go//')"
  if ! version_ge "$current" "$REQUIRED_GO"; then
    echo "[错误] Go 安装后版本仍不满足要求，当前: $current"
    exit 1
  fi
  echo "[2/6] Go 安装完成: $current"
}

install_runsc_if_missing() {
  if command_exists runsc; then
    echo "[3/6] runsc 已存在: $(runsc --version 2>/dev/null | head -n1 || true)"
    return 0
  fi

  if ! command_exists curl; then
    echo "[错误] 缺少 curl，无法下载 runsc"
    exit 1
  fi

  local arch
  case "$(uname -m)" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *)
      echo "[错误] 不支持的架构，无法自动安装 runsc: $(uname -m)"
      exit 1
      ;;
  esac

  local runsc_url tmp_path
  runsc_url="https://storage.googleapis.com/gvisor/releases/release/latest/${arch}/runsc"
  tmp_path="/tmp/runsc"

  echo "[3/6] 安装 runsc (${arch})"
  curl -fsSL "$runsc_url" -o "$tmp_path"
  chmod +x "$tmp_path"

  if [ "$(id -u)" -eq 0 ]; then
    install -m 0755 "$tmp_path" /usr/local/bin/runsc
  else
    mkdir -p "$HOME/.local/bin"
    install -m 0755 "$tmp_path" "$HOME/.local/bin/runsc"
    export PATH="$HOME/.local/bin:$PATH"
    if [ -f "$HOME/.bashrc" ] && ! grep -Fq 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.bashrc"; then
      printf '\n%s\n' 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    fi
    if [ -f "$HOME/.zshrc" ] && ! grep -Fq 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.zshrc"; then
      printf '\n%s\n' 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc"
    fi
  fi

  if ! command_exists runsc; then
    echo "[错误] runsc 安装后不可用"
    exit 1
  fi
  echo "[3/6] runsc 安装完成"
}

prepare_env_file() {
  echo "[4/6] 准备环境变量文件"
  if [ -f ".env.example" ] && [ ! -f ".env" ]; then
    cp .env.example .env
    echo "[4/6] 已创建 .env"
  else
    echo "[4/6] 已存在 .env 或无 .env.example，跳过"
  fi
}

go_mod_download() {
  echo "[5/6] 下载 Go 模块"
  go mod download
}

build_binary() {
  echo "[6/6] 构建可执行文件"
  go build -o skill-scanner ./cmd/server
}

post_check() {
  echo
  echo "初始化完成，关键能力检查结果："
  if command_exists docker; then
    echo "- docker: OK"
  else
    echo "- docker: MISSING"
  fi

  if command_exists runsc; then
    echo "- runsc: OK"
  else
    echo "- runsc: MISSING"
  fi

  if command_exists soffice || command_exists libreoffice; then
    echo "- libreoffice/soffice: OK"
  else
    echo "- libreoffice/soffice: MISSING"
  fi

  if command_exists fc-list && fc-list | grep -qi "Noto Sans CJK"; then
    echo "- fonts (Noto Sans CJK): OK"
  else
    echo "- fonts (Noto Sans CJK): MISSING"
  fi

  echo
  echo "启动命令："
  echo "  ./skill-scanner web"
  echo
  echo "访问地址："
  echo "  http://localhost:8880"
}

main() {
  echo "开始初始化 Skill Scanner 环境"
  install_apt_packages_if_missing
  install_or_upgrade_go_if_needed
  install_runsc_if_missing
  prepare_env_file
  go_mod_download
  build_binary
  post_check
}

main "$@"
