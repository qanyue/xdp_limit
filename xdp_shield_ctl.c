// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * xdp_shield_ctl.c — XDP Shield 用户态管理工具
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_shield_common.h"

static const char *pin_basedir = "/sys/fs/bpf/xdp_shield";
static int map_fd_rate      = -1;
static int map_fd_blacklist = -1;
static int map_fd_whitelist = -1;
static int map_fd_config    = -1;
static int map_fd_stats     = -1;

static int parse_u32_arg(const char *s, __u32 min, __u32 max, __u32 *out)
{
    char *end = NULL;
    unsigned long v;

    if (!s || !*s)
        return -1;

    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno || !end || *end != '\0')
        return -1;
    if (v < min || v > max)
        return -1;

    *out = (__u32)v;
    return 0;
}

static void close_maps(void)
{
    if (map_fd_rate >= 0) close(map_fd_rate);
    if (map_fd_blacklist >= 0) close(map_fd_blacklist);
    if (map_fd_whitelist >= 0) close(map_fd_whitelist);
    if (map_fd_config >= 0) close(map_fd_config);
    if (map_fd_stats >= 0) close(map_fd_stats);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "XDP Shield — L4 DDoS 防护管理工具\n"
        "\n"
        "用法: %s <命令> [参数...]\n"
        "\n"
        "加载/卸载:\n"
        "  load   <网卡> <BPF对象文件>\n"
        "  unload <网卡>\n"
        "\n"
        "黑名单管理:\n"
        "  blacklist-add <IP>\n"
        "  blacklist-del <IP>\n"
        "  blacklist-show\n"
        "\n"
        "白名单管理:\n"
        "  whitelist-add <IP>\n"
        "  whitelist-del <IP>\n"
        "  whitelist-show\n"
        "\n"
        "配置:\n"
        "  config-set <per_ip_syn> <global_syn>\n"
        "  config-show\n"
        "  enable\n"
        "  disable\n"
        "\n"
        "监控:\n"
        "  stats\n"
        "  stats-reset\n"
        "  monitor [间隔秒]\n"
        "  top [数量]\n"
        "\n"
        "示例:\n"
        "  %s load eth0 /opt/xdp-shield/xdp_shield_kern.o\n"
        "  %s blacklist-add 192.168.1.100\n"
        "  %s config-set 1000 200000\n"
        "  %s monitor 1\n"
        , prog, prog, prog, prog, prog);
}

static int ip_str_to_u32(const char *str, __u32 *out)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) != 1)
        return -1;
    *out = addr.s_addr;
    return 0;
}

static const char *ip_u32_to_str(__u32 ip)
{
    static char buf[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = ip };
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

static int open_pinned_map(const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", pin_basedir, name);
    int fd = bpf_obj_get(path);
    if (fd < 0) {
        fprintf(stderr, "错误: 无法打开 pinned map '%s': %s\n"
                        "提示: 请先执行 'load' 命令加载 XDP 程序\n",
                path, strerror(errno));
    }
    return fd;
}

static int open_all_maps(void)
{
    map_fd_rate      = open_pinned_map("ip_rate_map");
    map_fd_blacklist = open_pinned_map("blacklist_map");
    map_fd_whitelist = open_pinned_map("whitelist_map");
    map_fd_config    = open_pinned_map("config_map");
    map_fd_stats     = open_pinned_map("stats_map");

    if (map_fd_rate < 0 || map_fd_blacklist < 0 || map_fd_whitelist < 0 ||
        map_fd_config < 0 || map_fd_stats < 0)
        return -1;
    return 0;
}

static int cmd_load(const char *ifname, const char *obj_path)
{
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "错误: 网卡 '%s' 不存在\n", ifname);
        return 1;
    }

    if (mkdir(pin_basedir, 0755) && errno != EEXIST) {
        fprintf(stderr, "错误: 无法创建 pin 目录 '%s': %s\n", pin_basedir, strerror(errno));
        return 1;
    }

    struct bpf_object *obj = bpf_object__open(obj_path);
    if (!obj) {
        fprintf(stderr, "错误: 无法打开 BPF 对象文件 '%s': %s\n", obj_path, strerror(errno));
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "错误: 无法加载 BPF 程序: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_shield");
    if (!prog) {
        fprintf(stderr, "错误: 找不到 'xdp_shield' 程序\n");
        bpf_object__close(obj);
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    __u32 xdp_flags = XDP_FLAGS_SKB_MODE;
    if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL)) {
        fprintf(stderr, "错误: 无法将 XDP 程序附加到 %s: %s\n", ifname, strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);
        char pin_path[256];
        snprintf(pin_path, sizeof(pin_path), "%s/%s", pin_basedir, map_name);
        unlink(pin_path);
        if (bpf_map__pin(map, pin_path)) {
            fprintf(stderr, "警告: 无法 pin map '%s': %s\n", map_name, strerror(errno));
        }
    }

    {
        char path[256];
        snprintf(path, sizeof(path), "%s/config_map", pin_basedir);
        int cfg_fd = bpf_obj_get(path);
        if (cfg_fd >= 0) {
            __u32 key = 0;
            struct shield_config cfg = {
                .per_ip_pps_limit = DEFAULT_PER_IP_PPS_LIMIT,
                .global_pps_limit = DEFAULT_GLOBAL_PPS_LIMIT,
                .enabled          = 1,
                ._pad             = 0,
            };
            bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY);
            close(cfg_fd);
        }
    }

    printf("✓ XDP Shield 已加载到 %s (ifindex=%d)\n", ifname, ifindex);
    printf("  默认配置: 每IP SYN=%d/s  全局 SYN=%d/s\n", DEFAULT_PER_IP_PPS_LIMIT, DEFAULT_GLOBAL_PPS_LIMIT);
    bpf_object__close(obj);
    return 0;
}

static int cmd_unload(const char *ifname)
{
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "错误: 网卡 '%s' 不存在\n", ifname);
        return 1;
    }

    if (bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL) &&
        bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL) &&
        bpf_xdp_detach(ifindex, XDP_FLAGS_HW_MODE, NULL)) {
        fprintf(stderr, "警告: 无法从 %s 卸载 XDP 程序 (可能未加载)\n", ifname);
    }

    {
        const char *maps[] = {
            "ip_rate_map",
            "global_rate_map",
            "blacklist_map",
            "whitelist_map",
            "config_map",
            "stats_map",
        };
        char path[256];
        for (size_t i = 0; i < sizeof(maps) / sizeof(maps[0]); i++) {
            snprintf(path, sizeof(path), "%s/%s", pin_basedir, maps[i]);
            unlink(path);
        }
        rmdir(pin_basedir);
    }

    printf("✓ XDP Shield 已从 %s 卸载\n", ifname);
    return 0;
}

static int cmd_list_add(int map_fd, const char *ip_str, const char *list_name)
{
    __u32 ip;
    if (ip_str_to_u32(ip_str, &ip)) {
        fprintf(stderr, "错误: 无效的 IPv4 地址 '%s'\n", ip_str);
        return 1;
    }
    __u32 val = 1;
    if (bpf_map_update_elem(map_fd, &ip, &val, BPF_ANY)) {
        fprintf(stderr, "错误: 无法添加到%s: %s\n", list_name, strerror(errno));
        return 1;
    }
    printf("✓ 已添加 %s 到%s\n", ip_str, list_name);
    return 0;
}

static int cmd_list_del(int map_fd, const char *ip_str, const char *list_name)
{
    __u32 ip;
    if (ip_str_to_u32(ip_str, &ip)) {
        fprintf(stderr, "错误: 无效的 IPv4 地址 '%s'\n", ip_str);
        return 1;
    }
    if (bpf_map_delete_elem(map_fd, &ip)) {
        fprintf(stderr, "错误: %s中未找到 %s\n", list_name, ip_str);
        return 1;
    }
    printf("✓ 已从%s移除 %s\n", list_name, ip_str);
    return 0;
}

static int cmd_list_show(int map_fd, const char *list_name)
{
    __u32 key, next_key;
    __u32 *keyp = NULL;
    __u32 val;
    int count = 0;

    printf("── %s ──\n", list_name);
    while (bpf_map_get_next_key(map_fd, keyp, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
            printf("  %s\n", ip_u32_to_str(next_key));
            count++;
        }
        key = next_key;
        keyp = &key;
    }

    if (count == 0) printf("  (空)\n");
    else printf("  共 %d 条\n", count);
    return 0;
}

static int cmd_config_set(const char *per_ip_s, const char *global_s)
{
    __u32 key = 0;
    struct shield_config cfg;
    __u32 per_ip, global;

    if (bpf_map_lookup_elem(map_fd_config, &key, &cfg)) {
        cfg.enabled = 1;
        cfg._pad = 0;
    }

    if (parse_u32_arg(per_ip_s, 1, 10000000, &per_ip) ||
        parse_u32_arg(global_s, 1, 100000000, &global)) {
        fprintf(stderr, "错误: per_ip 必须是 1..10000000，global 必须是 1..100000000 的整数\n");
        return 1;
    }

    cfg.per_ip_pps_limit = per_ip;
    cfg.global_pps_limit = global;
    if (bpf_map_update_elem(map_fd_config, &key, &cfg, BPF_ANY)) {
        fprintf(stderr, "错误: 无法更新配置: %s\n", strerror(errno));
        return 1;
    }

    printf("✓ 速率限制已更新 (仅 TCP SYN 无ACK):\n");
    printf("  每IP: %u SYN/秒\n", cfg.per_ip_pps_limit);
    printf("  全局: %u SYN/秒\n", cfg.global_pps_limit);
    return 0;
}

static int cmd_config_show(void)
{
    __u32 key = 0;
    struct shield_config cfg;
    if (bpf_map_lookup_elem(map_fd_config, &key, &cfg)) {
        fprintf(stderr, "错误: 无法读取配置\n");
        return 1;
    }

    printf("── XDP Shield 配置 ──\n");
    printf("  状态:     %s\n", cfg.enabled ? "✓ 已启用" : "✗ 已禁用 (旁路模式)");
    printf("  每IP限制: %u SYN/秒\n", cfg.per_ip_pps_limit);
    printf("  全局限制: %u SYN/秒\n", cfg.global_pps_limit);
    return 0;
}

static int cmd_set_enabled(int enabled)
{
    __u32 key = 0;
    struct shield_config cfg;
    if (bpf_map_lookup_elem(map_fd_config, &key, &cfg)) {
        cfg.per_ip_pps_limit = DEFAULT_PER_IP_PPS_LIMIT;
        cfg.global_pps_limit = DEFAULT_GLOBAL_PPS_LIMIT;
        cfg._pad = 0;
    }
    cfg.enabled = enabled ? 1 : 0;
    if (bpf_map_update_elem(map_fd_config, &key, &cfg, BPF_ANY)) {
        fprintf(stderr, "错误: 无法更新配置: %s\n", strerror(errno));
        return 1;
    }
    printf("✓ XDP Shield 已%s\n", enabled ? "启用" : "禁用 (旁路模式)");
    return 0;
}

static const char *stats_names[STATS_MAX] = {
    [STATS_PASSED]               = "放行",
    [STATS_DROPPED_BLACKLIST]    = "丢弃(黑名单)",
    [STATS_DROPPED_PER_IP_LIMIT] = "丢弃(每IP SYN限速)",
    [STATS_DROPPED_GLOBAL_LIMIT] = "丢弃(全局 SYN限速)",
    [STATS_WHITELISTED]          = "白名单放行",
    [STATS_TOTAL_PROCESSED]      = "总处理",
};

static int read_stats(__u64 totals[STATS_MAX])
{
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) return -1;

    __u64 *percpu_vals = calloc(num_cpus, sizeof(__u64));
    if (!percpu_vals) return -1;

    for (__u32 i = 0; i < STATS_MAX; i++) {
        totals[i] = 0;
        if (bpf_map_lookup_elem(map_fd_stats, &i, percpu_vals) == 0) {
            for (int c = 0; c < num_cpus; c++)
                totals[i] += percpu_vals[c];
        }
    }
    free(percpu_vals);
    return 0;
}

static int cmd_stats(void)
{
    __u64 totals[STATS_MAX];
    if (read_stats(totals)) return 1;

    __u64 total_dropped = totals[STATS_DROPPED_BLACKLIST] +
                          totals[STATS_DROPPED_PER_IP_LIMIT] +
                          totals[STATS_DROPPED_GLOBAL_LIMIT];

    printf("══════════════════════════════════════════\n");
    printf("  XDP Shield 统计\n");
    printf("══════════════════════════════════════════\n");
    for (int i = 0; i < STATS_MAX; i++)
        printf("  %-20s %'12llu\n", stats_names[i], (unsigned long long)totals[i]);
    printf("──────────────────────────────────────────\n");
    printf("  %-20s %'12llu\n", "总丢弃", (unsigned long long)total_dropped);
    if (totals[STATS_TOTAL_PROCESSED] > 0) {
        double drop_rate = 100.0 * total_dropped / totals[STATS_TOTAL_PROCESSED];
        printf("  %-20s %11.2f%%\n", "丢弃率", drop_rate);
    }
    printf("══════════════════════════════════════════\n");
    return 0;
}

static int cmd_stats_reset(void)
{
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) return 1;

    __u64 *zeros = calloc(num_cpus, sizeof(__u64));
    if (!zeros) return 1;
    for (__u32 i = 0; i < STATS_MAX; i++)
        bpf_map_update_elem(map_fd_stats, &i, zeros, BPF_ANY);
    free(zeros);
    printf("✓ 统计计数器已重置\n");
    return 0;
}

static volatile int running = 1;
static void sig_handler(int sig) { (void)sig; running = 0; }

static int cmd_monitor(int interval)
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    __u64 prev[STATS_MAX] = {0};
    __u64 curr[STATS_MAX];
    printf("XDP Shield 实时监控 (每 %d 秒刷新, Ctrl+C 退出)\n\n", interval);

    while (running) {
        if (read_stats(curr)) return 1;
        printf("\033[2J\033[H");
        printf("═══════════════════════════════════════════════════════════\n");
        printf("  XDP Shield 实时监控  (每 %d 秒)    Ctrl+C 退出\n", interval);
        printf("═══════════════════════════════════════════════════════════\n");
        printf("  %-24s %12s %12s\n", "指标", "总计", "速率(/s)");
        printf("───────────────────────────────────────────────────────────\n");
        for (int i = 0; i < STATS_MAX; i++) {
            __u64 delta = curr[i] - prev[i];
            printf("  %-24s %12llu %12.1f\n",
                   stats_names[i], (unsigned long long)curr[i], (double)delta / interval);
        }
        __u64 total_dropped = curr[STATS_DROPPED_BLACKLIST] +
                              curr[STATS_DROPPED_PER_IP_LIMIT] +
                              curr[STATS_DROPPED_GLOBAL_LIMIT];
        __u64 prev_dropped  = prev[STATS_DROPPED_BLACKLIST] +
                              prev[STATS_DROPPED_PER_IP_LIMIT] +
                              prev[STATS_DROPPED_GLOBAL_LIMIT];
        printf("───────────────────────────────────────────────────────────\n");
        printf("  %-24s %12llu %12.1f\n",
               "总丢弃", (unsigned long long)total_dropped,
               (double)(total_dropped - prev_dropped) / interval);
        if (curr[STATS_TOTAL_PROCESSED] > 0) {
            double drop_rate = 100.0 * total_dropped / curr[STATS_TOTAL_PROCESSED];
            printf("  %-24s              %11.2f%%\n", "丢弃率", drop_rate);
        }
        printf("═══════════════════════════════════════════════════════════\n");
        memcpy(prev, curr, sizeof(prev));
        sleep(interval);
    }
    printf("\n监控已停止\n");
    return 0;
}

static int cmd_top(int count)
{
    struct { __u32 ip; struct ip_rate_info info; } entries[MAX_TRACKED_IPS];
    int n = 0;
    __u32 key, next_key;
    __u32 *keyp = NULL;

    while (bpf_map_get_next_key(map_fd_rate, keyp, &next_key) == 0 && n < MAX_TRACKED_IPS) {
        struct ip_rate_info info;
        if (bpf_map_lookup_elem(map_fd_rate, &next_key, &info) == 0) {
            entries[n].ip = next_key;
            entries[n].info = info;
            n++;
        }
        key = next_key;
        keyp = &key;
    }

    for (int i = 0; i < n - 1; i++) {
        for (int j = i + 1; j < n; j++) {
            if (entries[j].info.total_count > entries[i].info.total_count) {
                typeof(entries[0]) tmp = entries[i];
                entries[i] = entries[j];
                entries[j] = tmp;
            }
        }
    }

    if (count > n) count = n;
    printf("── 流量 Top %d IP (当前窗口) ──\n", count);
    printf("  %-18s %10s\n", "IP 地址", "总/s");
    printf("  ───────────────────────────────\n");
    for (int i = 0; i < count; i++)
        printf("  %-18s %10u\n", ip_u32_to_str(entries[i].ip), entries[i].info.total_count);
    if (n == 0) printf("  (无数据)\n");
    printf("  共跟踪 %d 个 IP\n", n);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(argv[0]); return 1; }
    const char *cmd = argv[1];

    if (strcmp(cmd, "load") == 0) {
        if (argc < 4) { fprintf(stderr, "用法: %s load <网卡> <BPF对象文件>\n", argv[0]); return 1; }
        return cmd_load(argv[2], argv[3]);
    }
    if (strcmp(cmd, "unload") == 0) {
        if (argc < 3) { fprintf(stderr, "用法: %s unload <网卡>\n", argv[0]); return 1; }
        return cmd_unload(argv[2]);
    }

    if (open_all_maps()) return 1;

    if (strcmp(cmd, "blacklist-add") == 0) {
        if (argc < 3) { fprintf(stderr, "用法: %s blacklist-add <IP>\n", argv[0]); return 1; }
        return cmd_list_add(map_fd_blacklist, argv[2], "黑名单");
    }
    if (strcmp(cmd, "blacklist-del") == 0) {
        if (argc < 3) { fprintf(stderr, "用法: %s blacklist-del <IP>\n", argv[0]); return 1; }
        return cmd_list_del(map_fd_blacklist, argv[2], "黑名单");
    }
    if (strcmp(cmd, "blacklist-show") == 0) return cmd_list_show(map_fd_blacklist, "黑名单");

    if (strcmp(cmd, "whitelist-add") == 0) {
        if (argc < 3) { fprintf(stderr, "用法: %s whitelist-add <IP>\n", argv[0]); return 1; }
        return cmd_list_add(map_fd_whitelist, argv[2], "白名单");
    }
    if (strcmp(cmd, "whitelist-del") == 0) {
        if (argc < 3) { fprintf(stderr, "用法: %s whitelist-del <IP>\n", argv[0]); return 1; }
        return cmd_list_del(map_fd_whitelist, argv[2], "白名单");
    }
    if (strcmp(cmd, "whitelist-show") == 0) return cmd_list_show(map_fd_whitelist, "白名单");

    if (strcmp(cmd, "config-set") == 0) {
        if (argc < 4) { fprintf(stderr, "用法: %s config-set <每IP/s> <全局/s>\n", argv[0]); return 1; }
        return cmd_config_set(argv[2], argv[3]);
    }
    if (strcmp(cmd, "config-show") == 0) return cmd_config_show();
    if (strcmp(cmd, "enable") == 0)  return cmd_set_enabled(1);
    if (strcmp(cmd, "disable") == 0) return cmd_set_enabled(0);
    if (strcmp(cmd, "stats") == 0) return cmd_stats();
    if (strcmp(cmd, "stats-reset") == 0) return cmd_stats_reset();

    if (strcmp(cmd, "monitor") == 0) {
        __u32 interval_u32 = 2;
        if (argc >= 3 && parse_u32_arg(argv[2], 1, 3600, &interval_u32)) {
            fprintf(stderr, "错误: monitor 间隔必须是 1..3600 的整数秒\n");
            return 1;
        }
        int interval = (int)interval_u32;
        if (interval < 1) interval = 1;
        return cmd_monitor(interval);
    }

    if (strcmp(cmd, "top") == 0) {
        __u32 count_u32 = 20;
        if (argc >= 3 && parse_u32_arg(argv[2], 1, MAX_TRACKED_IPS, &count_u32)) {
            fprintf(stderr, "错误: top 数量必须是 1..%d 的整数\n", MAX_TRACKED_IPS);
            return 1;
        }
        int count = (int)count_u32;
        if (count < 1) count = 1;
        return cmd_top(count);
    }

    fprintf(stderr, "未知命令: '%s'\n\n", cmd);
    usage(argv[0]);
    close_maps();
    return 1;
}
