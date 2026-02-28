// xdp_min_rate_limit.c
// clang -O2 -g -target bpf -c xdp_min_rate_limit.c -o xdp_min_rate_limit.o

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>   // defines IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, ...

char LICENSE[] SEC("license") = "GPL";

#define NS_PER_SEC 1000000000ULL

// 你可以按机器能力调小/调大
#define GLOBAL_PPS_LIMIT  500000U   // 全局每秒 50万包
#define PER_IP_PPS_LIMIT   20000U   // 单IP每秒 2万包

struct rate_val {
    __u64 window_start_ns;
    __u32 packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_val);
} global_rate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);              // saddr
    __type(value, struct rate_val);
} ip_rate SEC(".maps");

static __always_inline int allow_packet(struct rate_val *v, __u32 limit, __u64 now_ns) {
    if (!v) return 1;

    if (now_ns - v->window_start_ns >= NS_PER_SEC) {
        v->window_start_ns = now_ns;
        v->packets = 1;
        return 1;
    }

    if (v->packets >= limit)
        return 0;

    v->packets++;
    return 1;
}

SEC("xdp")
int xdp_syn_udp_guard(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // 只处理 TCP SYN 或 UDP
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = (void *)iph + (iph->ihl * 4);
        if ((void *)(th + 1) > data_end)
            return XDP_PASS;
        if (!th->syn || th->ack)
            return XDP_PASS; // 只限速 SYN(非ACK)
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *uh = (void *)iph + (iph->ihl * 4);
        if ((void *)(uh + 1) > data_end)
            return XDP_PASS;
    } else {
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();

    // 1) 全局限速
    __u32 gk = 0;
    struct rate_val *gv = bpf_map_lookup_elem(&global_rate, &gk);
    if (!gv) {
        struct rate_val init = {.window_start_ns = now, .packets = 1};
        bpf_map_update_elem(&global_rate, &gk, &init, BPF_ANY);
    } else {
        if (!allow_packet(gv, GLOBAL_PPS_LIMIT, now))
            return XDP_DROP;
    }

    // 2) 源IP限速
    __u32 sip = iph->saddr;
    struct rate_val *iv = bpf_map_lookup_elem(&ip_rate, &sip);
    if (!iv) {
        struct rate_val init = {.window_start_ns = now, .packets = 1};
        bpf_map_update_elem(&ip_rate, &sip, &init, BPF_ANY);
    } else {
        if (!allow_packet(iv, PER_IP_PPS_LIMIT, now))
            return XDP_DROP;
    }

    return XDP_PASS;
}