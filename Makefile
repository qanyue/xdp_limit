# ──────────────────────────────────────────────────────────────
#  XDP Shield — Makefile
#  编译 eBPF 内核态程序 + 用户态管理工具
# ──────────────────────────────────────────────────────────────

CLANG      ?= clang
LLC        ?= llc
CC         ?= gcc
STRIP      ?= llvm-strip

# 内核头文件路径 (自动检测)
KERN_HEADERS := $(shell ls -d /usr/include/$(shell uname -m)-linux-gnu 2>/dev/null || echo /usr/include)

# eBPF 编译选项
BPF_CFLAGS := -O2 -g -target bpf \
              -D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/') \
              -I$(KERN_HEADERS) \
              -Wall -Wno-unused-value -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types

# 用户态编译选项
USER_CFLAGS  := -O2 -Wall -I.
USER_LDFLAGS := -lbpf -lelf -lz

# 输出目录
BUILD_DIR := build

# 目标文件
BPF_OBJ   := $(BUILD_DIR)/xdp_shield_kern.o
USER_BIN  := $(BUILD_DIR)/xdp-shield-ctl

.PHONY: all clean install bpf user

all: bpf user

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# ── 编译 eBPF 内核态程序 ──
bpf: $(BPF_OBJ)

$(BPF_OBJ): xdp_shield_kern.c xdp_shield_common.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# ── 编译用户态管理工具 ──
user: $(USER_BIN)

$(USER_BIN): xdp_shield_ctl.c xdp_shield_common.h | $(BUILD_DIR)
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

# ── 安装 ──
install: all
	install -d /opt/xdp-shield/
	install -m 644 $(BPF_OBJ) /opt/xdp-shield/
	install -m 755 $(USER_BIN) /usr/local/bin/
	install -m 755 xdp-shield.sh /usr/local/bin/
	@echo "✓ 安装完成: /opt/xdp-shield/ + /usr/local/bin/xdp-shield-ctl"

# ── 清理 ──
clean:
	rm -rf $(BUILD_DIR)
