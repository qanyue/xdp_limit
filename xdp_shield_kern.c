// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * xdp_shield_kern.c — XDP/eBPF L4 DDoS 防护程序
 *
 * 功能概述:
 *   1. 每 IP 速率限制   — 每源 IP 总包速率限制
 *   2. 全局速率限制     — 全流量总 PPS 限制
 *   3. IP 黑名单        — 命中即丢弃
 *   4. IP 白名单        — 命中即放行 (跳过所有检查)
 *   5. 实时统计         — per-CPU 计数器, 用户态可读取
 *
 * 设计要点:
 *   - 使用 per-CPU array 做统计, 避免锁竞争
 *   - 使用 LRU hash 做 IP 速率跟踪, 自动淘汰冷条目
 *   - 所有阈值通过 config map 可在线调整, 无需重新加载
 *   - 白名单 IP 完全绕过所有检查, 零开销
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_shield_common.h"

/* ═══════════════════════════════════════════════
 *  BPF Maps
 * ═══════════════════════════════════════════════ */

/* 1) 每 IP 速率跟踪 (LRU hash — 满时自动淘汰最久未用条目) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_IPS);
    __type(key, __u32);                     /* src IPv4 */
    __type(value, struct ip_rate_info);
} ip_rate_map SEC(".maps");

/* 2) 全局速率跟踪 (array, index 0) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_rate_info);
} global_rate_map SEC(".maps");

/* 3) IP 黑名单 (hash set — value 为 dummy) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLACKLIST_IPS);
    __type(key, __u32);                     /* IPv4 地址 */
    __type(value, __u32);                   /* dummy = 1 */
} blacklist_map SEC(".maps");
/* 4) IP 白名单 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_WHITELIST_IPS);
    __type(key, __u32);
    __type(value, __u32);
} whitelist_map SEC(".maps");

/* 5) 全局配置 (array, index 0) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct shield_config);
} config_map SEC(".maps");

/* 6) per-CPU 统计计数器 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

/* ═══════════════════════════════════════════════
 *  辅助函数
 * ═══════════════════════════════════════════════ */

/* 递增统计计数器 */
static __always_inline void stats_inc(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val)
        (*val)++;
}

/* 获取配置, 若 map 为空则返回默认值 */
static __always_inline void get_config(struct shield_config *cfg)
{
    __u32 key = 0;
    struct shield_config *stored = bpf_map_lookup_elem(&config_map, &key);

    if (stored) {
        cfg->per_ip_pps_limit = stored->per_ip_pps_limit;
        cfg->global_pps_limit = stored->global_pps_limit;
        cfg->enabled          = stored->enabled;
        cfg->_pad             = stored->_pad;
    } else {
        cfg->per_ip_pps_limit = DEFAULT_PER_IP_PPS_LIMIT;
        cfg->global_pps_limit = DEFAULT_GLOBAL_PPS_LIMIT;
        cfg->enabled          = 1;
        cfg->_pad             = 0;
    }
}

/* ═══════════════════════════════════════════════
 *  XDP 主程序
 * ═══════════════════════════════════════════════ */

SEC("xdp")
int xdp_shield(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ── 统计: 总处理包数 ── */
    stats_inc(STATS_TOTAL_PROCESSED);

    /* ── 读取配置 ── */
    struct shield_config cfg;
    get_config(&cfg);

    /* 全局旁路开关 */
    if (!cfg.enabled)
        return XDP_PASS;

    /* ══════════════════════════════════════
     *  L2: 解析以太网头
     * ══════════════════════════════════════ */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 仅处理 IPv4 (IPv6 可后续扩展) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* ══════════════════════════════════════
     *  L3: 解析 IP 头
     * ══════════════════════════════════════ */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    /* 变长 IP 头: 计算实际长度 */
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;
    if ((void *)iph + ip_hdr_len > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;

    /* ══════════════════════════════════════
     *  白名单检查 (最高优先级, 命中即放行)
     * ══════════════════════════════════════ */
    if (bpf_map_lookup_elem(&whitelist_map, &src_ip)) {
        stats_inc(STATS_WHITELISTED);
        stats_inc(STATS_PASSED);
        return XDP_PASS;
    }

    /* ══════════════════════════════════════
     *  黑名单检查 (命中即丢弃)
     * ══════════════════════════════════════ */
    if (bpf_map_lookup_elem(&blacklist_map, &src_ip)) {
        stats_inc(STATS_DROPPED_BLACKLIST);
        return XDP_DROP;
    }

    /* ══════════════════════════════════════
     *  速率限制检查 (无协议/端口区分)
     * ══════════════════════════════════════ */

    __u64 now = bpf_ktime_get_ns();
    __u32 global_key = 0;
    struct global_rate_info *global_info = bpf_map_lookup_elem(&global_rate_map, &global_key);
    if (global_info) {
        if (now - global_info->window_start < TIME_WINDOW_NS) {
            global_info->total_count++;
            if (global_info->total_count > cfg.global_pps_limit) {
                stats_inc(STATS_DROPPED_GLOBAL_LIMIT);
                return XDP_DROP;
            }
        } else {
            global_info->window_start = now;
            global_info->total_count  = 1;
        }
    } else {
        struct global_rate_info new_global;
        __builtin_memset(&new_global, 0, sizeof(new_global));
        new_global.window_start = now;
        new_global.total_count  = 1;
        bpf_map_update_elem(&global_rate_map, &global_key, &new_global, BPF_ANY);
    }

    struct ip_rate_info *info = bpf_map_lookup_elem(&ip_rate_map, &src_ip);

    if (info) {
        /* 检查是否在同一时间窗口内 */
        if (now - info->window_start < TIME_WINDOW_NS) {
            /* 同一窗口: 递增计数 */
            info->total_count++;
            if (info->total_count > cfg.per_ip_pps_limit) {
                stats_inc(STATS_DROPPED_PER_IP_LIMIT);
                return XDP_DROP;
            }

        } else {
            /* 新窗口: 重置计数器 */
            info->window_start = now;
            info->total_count  = 1;
        }

    } else {
        /* 新 IP: 初始化跟踪条目 */
        struct ip_rate_info new_info;
        __builtin_memset(&new_info, 0, sizeof(new_info));
        new_info.window_start = now;
        new_info.total_count  = 1;
        bpf_map_update_elem(&ip_rate_map, &src_ip, &new_info, BPF_ANY);
    }

    /* 通过所有检查, 放行 */
    stats_inc(STATS_PASSED);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
