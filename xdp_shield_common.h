/* SPDX-License-Identifier: GPL-2.0-or-later
 * xdp_shield_common.h — 内核态 / 用户态共享数据结构
 *
 * 本文件定义了 XDP Shield 中 eBPF map 使用的 key/value 结构体，
 * 以及用户态管理工具与内核态 XDP 程序之间共享的常量。
 */

#ifndef __XDP_SHIELD_COMMON_H__
#define __XDP_SHIELD_COMMON_H__

/* ─────────────────────────────────────────────
 *  常量定义
 * ───────────────────────────────────────────── */

/* 默认速率限制阈值（每秒 SYN 包数，SYN=1 且 ACK=0） */
#define DEFAULT_PER_IP_PPS_LIMIT    100    /* 每 IP SYN/秒 */
#define DEFAULT_GLOBAL_PPS_LIMIT    50000  /* 全局 SYN/秒  */

/* 时间窗口 (纳秒) */
#define TIME_WINDOW_NS              1000000000ULL   /* 1 秒 */

/* Map 容量 */
#define MAX_TRACKED_IPS             65536
#define MAX_BLACKLIST_IPS           4096
#define MAX_WHITELIST_IPS           4096

/* 统计计数器索引 */
#define STATS_PASSED                0
#define STATS_DROPPED_BLACKLIST     1
#define STATS_DROPPED_PER_IP_LIMIT  2
#define STATS_DROPPED_GLOBAL_LIMIT  3
#define STATS_WHITELISTED           4
#define STATS_TOTAL_PROCESSED       5
#define STATS_MAX                   6

/* ─────────────────────────────────────────────
 *  数据结构
 * ───────────────────────────────────────────── */

/* 每 IP 的速率跟踪条目 */
struct ip_rate_info {
    __u64 window_start;         /* 当前窗口起始时间 (ns) */
    __u32 total_count;          /* 当前窗口总包计数 */
    __u32 _pad;                 /* 对齐填充 */
};

/* 全局速率跟踪条目 */
struct global_rate_info {
    __u64 window_start;         /* 当前窗口起始时间 (ns) */
    __u32 total_count;          /* 当前窗口总包计数 */
    __u32 _pad;                 /* 对齐填充 */
};

/* 可配置的速率限制参数 (存储在 config map 中) */
struct shield_config {
    __u32 per_ip_pps_limit;     /* 每 IP SYN/秒上限 (SYN=1 且 ACK=0) */
    __u32 global_pps_limit;     /* 全局 SYN/秒上限 (SYN=1 且 ACK=0) */
    __u32 enabled;              /* 全局开关: 1=启用, 0=旁路 */
    __u32 _pad;                 /* 对齐填充 */
};

#endif /* __XDP_SHIELD_COMMON_H__ */
