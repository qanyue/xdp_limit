#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES 10000
#define SYN_RATE_LIMIT 100  // SYN packets per second per IP

struct syn_tracker {
    __u64 timestamp;
    __u32 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);  // Source IP
    __type(value, struct syn_tracker);
} syn_flood_map SEC(".maps");

static __always_inline int parse_tcp(void *data, void *data_end,
                                     struct iphdr **iph, struct tcphdr **tcph) {
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    *iph = (void *)(eth + 1);
    if ((void *)(*iph + 1) > data_end)
        return -1;

    if ((*iph)->protocol != IPPROTO_TCP)
        return -1;

    *tcph = (void *)(*iph) + sizeof(struct iphdr);
    if ((void *)(*tcph + 1) > data_end)
        return -1;

    return 0;
}

SEC("xdp")
int xdp_syn_flood_protect(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct iphdr *iph;
    struct tcphdr *tcph;

    if (parse_tcp(data, data_end, &iph, &tcph) < 0)
        return XDP_PASS;

    // Only process SYN packets (without ACK)
    if (!(tcph->syn && !tcph->ack))
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct syn_tracker *tracker = bpf_map_lookup_elem(&syn_flood_map, &src_ip);

    if (tracker) {
        __u64 elapsed = now - tracker->timestamp;

        // Reset counter if more than 1 second has passed
        if (elapsed > 1000000000ULL) {
            tracker->timestamp = now;
            tracker->count = 1;
            return XDP_PASS;
        }

        // Check if rate limit exceeded
        if (tracker->count >= SYN_RATE_LIMIT) {
            // Log dropped SYN (optional, impacts performance)
            // bpf_printk("Dropping SYN from %pI4", &src_ip);
            return XDP_DROP;
        }

        tracker->count++;
    } else {
        // New source IP
        struct syn_tracker new_tracker = {
            .timestamp = now,
            .count = 1
        };
        bpf_map_update_elem(&syn_flood_map, &src_ip, &new_tracker, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
