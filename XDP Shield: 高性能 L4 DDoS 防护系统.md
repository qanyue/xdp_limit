# XDP Shield: 高性能 L4 DDoS 防护系统

**XDP Shield** 是一个基于 Linux XDP/eBPF 的高性能流量防护方案。  
当前版本核心策略已简化为两层限速：

- **单 IP 限速**（每个源 IP 每秒包数上限）
- **全局限速**（整机总包速率上限）

不再按端口、协议（SYN/UDP）区分规则。

---

## 核心功能

- **高性能过滤**：在 XDP 层尽早处理数据包，减轻协议栈与应用压力。
- **双层限速**：
  - 每 IP 总包速率限制（Per-IP PPS）
  - 全局总包速率限制（Global PPS）
- **黑白名单**：
  - 白名单命中直接放行
  - 黑名单命中直接丢弃
- **动态配置**：通过 `xdp-shield-ctl` 在线修改阈值与开关，无需重载程序。
- **实时监控**：支持统计、实时刷新监控与 Top IP 观察。

## 工作原理

XDP 程序对 IPv4 包按以下顺序处理：

1. 白名单检查（命中即放行）
2. 黑名单检查（命中即丢弃）
3. 全局限速检查（全局窗口计数）
4. 单 IP 限速检查（按源 IP 窗口计数）
5. 通过后放行

用户态控制工具通过 BPF map 完成配置与观测：

- `config_map`：开关与阈值（per_ip/global）
- `ip_rate_map`：每 IP 窗口统计
- `global_rate_map`：全局窗口统计
- `stats_map`：统计计数器
- `blacklist_map` / `whitelist_map`：名单控制

## 安装与编译

环境要求：

- Linux Kernel >= 5.4（建议 >= 5.10）
- clang / llvm
- libbpf / libelf

编译：

```bash
make clean
make all
```

输出：

- `build/xdp_shield_kern.o`
- `build/xdp-shield-ctl`

## 快速使用

### 加载与卸载

```bash
sudo ./build/xdp-shield-ctl load eth0 ./build/xdp_shield_kern.o
sudo ./build/xdp-shield-ctl unload eth0
```

### 配置限速（单 IP + 全局）

```bash
# config-set <per_ip> <global>
sudo ./build/xdp-shield-ctl config-set 1000 200000
sudo ./build/xdp-shield-ctl config-show
```

### 黑白名单

```bash
sudo ./build/xdp-shield-ctl blacklist-add 203.0.113.10
sudo ./build/xdp-shield-ctl whitelist-add 198.51.100.5
sudo ./build/xdp-shield-ctl blacklist-show
sudo ./build/xdp-shield-ctl whitelist-show
```

### 监控

```bash
sudo ./build/xdp-shield-ctl stats
sudo ./build/xdp-shield-ctl monitor 2
sudo ./build/xdp-shield-ctl top 10
```

## 脚本

项目内 `xdp-shield.sh` 已同步为新模型：

- `setup-caddy` 不再配置端口规则
- 默认推荐阈值：`config-set 1000 200000`

## 目录结构（当前）

```text
.
├── Makefile
├── xdp-shield.sh
├── xdp_shield_common.h
├── xdp_shield_kern.c
├── xdp_shield_ctl.c
└── build/
```
