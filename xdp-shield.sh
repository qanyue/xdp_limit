#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  xdp-shield.sh — XDP Shield 快速部署 / 管理脚本
#
#  用法:
#    ./xdp-shield.sh install          安装依赖 + 编译
#    ./xdp-shield.sh start [网卡]     加载 XDP 程序
#    ./xdp-shield.sh stop  [网卡]     卸载 XDP 程序
#    ./xdp-shield.sh status           查看状态和统计
#    ./xdp-shield.sh setup-caddy [网卡]  一键为 Caddy 配置防护
# ──────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
BUILD_DIR="${PROJECT_DIR}/build"
BPF_OBJ="${BUILD_DIR}/xdp_shield_kern.o"
CTL_BIN="${BUILD_DIR}/xdp-shield-ctl"

# 默认网卡: 取默认路由的出口网卡
DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}' || echo "eth0")

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ── 安装依赖 + 编译 ──
cmd_install() {
    log_info "安装编译依赖..."

    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq \
            clang llvm libbpf-dev libelf-dev zlib1g-dev \
            linux-headers-$(uname -r) build-essential \
            2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y \
            clang llvm libbpf-devel elfutils-libelf-devel zlib-devel \
            kernel-headers gcc make \
            2>/dev/null || true
    elif command -v yum &>/dev/null; then
        sudo yum install -y \
            clang llvm libbpf-devel elfutils-libelf-devel zlib-devel \
            kernel-headers gcc make \
            2>/dev/null || true
    else
        log_error "不支持的包管理器, 请手动安装: clang llvm libbpf-dev libelf-dev"
        exit 1
    fi

    log_info "编译 XDP Shield..."
    cd "$PROJECT_DIR"
    make clean
    make all

    if [[ -f "$BPF_OBJ" ]] && [[ -f "$CTL_BIN" ]]; then
        log_info "编译成功!"
        log_info "  eBPF 对象: $BPF_OBJ"
        log_info "  管理工具: $CTL_BIN"
    else
        log_error "编译失败, 请检查错误信息"
        exit 1
    fi
}

# ── 加载 XDP 程序 ──
cmd_start() {
    local iface="${1:-$DEFAULT_IFACE}"

    if [[ ! -f "$BPF_OBJ" ]] || [[ ! -f "$CTL_BIN" ]]; then
        log_error "请先运行 '$0 install' 编译项目"
        exit 1
    fi

    log_info "加载 XDP Shield 到 $iface ..."
    sudo "$CTL_BIN" load "$iface" "$BPF_OBJ"
}

# ── 卸载 XDP 程序 ──
cmd_stop() {
    local iface="${1:-$DEFAULT_IFACE}"

    if [[ ! -f "$CTL_BIN" ]]; then
        log_error "管理工具不存在, 请先编译"
        exit 1
    fi

    log_info "卸载 XDP Shield 从 $iface ..."
    sudo "$CTL_BIN" unload "$iface"
}

# ── 查看状态 ──
cmd_status() {
    if [[ ! -f "$CTL_BIN" ]]; then
        log_error "管理工具不存在"
        exit 1
    fi

    echo ""
    sudo "$CTL_BIN" config-show
    echo ""
    sudo "$CTL_BIN" stats
    echo ""
    sudo "$CTL_BIN" blacklist-show
    echo ""
    sudo "$CTL_BIN" whitelist-show
}

# ── 一键为 Caddy 配置防护 ──
cmd_setup_caddy() {
    local iface="${1:-$DEFAULT_IFACE}"

    log_info "═══════════════════════════════════════════"
    log_info "  XDP Shield — Caddy 一键防护配置"
    log_info "═══════════════════════════════════════════"

    # 1) 编译 (如果还没编译)
    if [[ ! -f "$BPF_OBJ" ]]; then
        cmd_install
    fi

    # 2) 加载
    cmd_start "$iface"

    # 3) 设置推荐的速率限制
    log_info "设置推荐的速率限制..."
    sudo "$CTL_BIN" config-set 1000 200000

    # 4) 白名单本机回环
    log_info "白名单本机地址..."
    sudo "$CTL_BIN" whitelist-add 127.0.0.1 || true

    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "  Caddy 防护配置完成!"
    log_info "═══════════════════════════════════════════"
    echo ""
    log_info "当前配置:"
    sudo "$CTL_BIN" config-show
    echo ""
    log_info "常用命令:"
    echo "  sudo $CTL_BIN monitor          # 实时监控"
    echo "  sudo $CTL_BIN top              # 查看流量 Top IP"
    echo "  sudo $CTL_BIN blacklist-add IP  # 手动封禁 IP"
    echo "  sudo $CTL_BIN whitelist-add IP  # 添加白名单"
    echo "  sudo $CTL_BIN config-set 1000 200000 # 调整限速"
    echo "  $0 stop $iface                 # 停止防护"
}

# ── 主入口 ──
case "${1:-help}" in
    install)
        cmd_install
        ;;
    start)
        cmd_start "${2:-}"
        ;;
    stop)
        cmd_stop "${2:-}"
        ;;
    status)
        cmd_status
        ;;
    setup-caddy)
        cmd_setup_caddy "${2:-}"
        ;;
    monitor)
        sudo "$CTL_BIN" monitor "${2:-2}"
        ;;
    top)
        sudo "$CTL_BIN" top "${2:-20}"
        ;;
    *)
        echo "XDP Shield — L4 DDoS 防护"
        echo ""
        echo "用法: $0 <命令> [参数]"
        echo ""
        echo "命令:"
        echo "  install              安装依赖并编译"
        echo "  start [网卡]         加载 XDP 程序"
        echo "  stop  [网卡]         卸载 XDP 程序"
        echo "  status               查看状态和统计"
        echo "  setup-caddy [网卡]   一键为 Caddy 配置防护"
        echo "  monitor [间隔]       实时监控"
        echo "  top [数量]           查看流量 Top IP"
        echo ""
        echo "示例:"
        echo "  $0 install            # 首次安装"
        echo "  $0 setup-caddy eth0   # 一键配置"
        echo "  $0 status             # 查看状态"
        ;;
esac
