// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct ip_key
{
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
};

struct ip_value
{
    __u64 packet_size;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ip_key);
    __type(value, struct ip_value);
    __uint(max_entries, 4096);
} ip_map SEC(".maps");

static __always_inline int handle_packet(struct __sk_buff *skb)
{
    unsigned char iphdr_buf[sizeof(struct iphdr) + 64];

    if (bpf_skb_load_bytes(skb, 0, iphdr_buf, sizeof(iphdr_buf)) < 0)
        return 1;

    struct iphdr *iph = (struct iphdr *)iphdr_buf;

    if (iph->version != 4)
        return 1;

    __u32 saddr = iph->saddr;
    __u32 daddr = iph->daddr;
    __u8 proto = iph->protocol;
    __u8 ihl = iph->ihl * 4;

    struct ip_key key = {};
    key.src_ip = saddr;
    key.dest_ip = daddr;

    if (proto == IPPROTO_TCP)
    {
        struct tcphdr *th = (void *)iphdr_buf + ihl;
        key.src_port = bpf_ntohs(th->source);
        key.dest_port = bpf_ntohs(th->dest);
    }
    else if (proto == IPPROTO_UDP)
    {
        struct udphdr *uh = (void *)iphdr_buf + ihl;
        key.src_port = bpf_ntohs(uh->source);
        key.dest_port = bpf_ntohs(uh->dest);
    }
    else
    {
        return 1;
    }

    __u64 pkt_size = skb->len;

    struct ip_value *v = bpf_map_lookup_elem(&ip_map, &key);
    if (v)
        __sync_fetch_and_add(&v->packet_size, pkt_size);
    else
    {
        struct ip_value newv = {.packet_size = pkt_size};
        bpf_map_update_elem(&ip_map, &key, &newv, BPF_ANY);
    }

    return 1; // allow packet
}

SEC("cgroup_skb/egress")
int egress_connection_tracker(struct __sk_buff *skb)
{
    return handle_packet(skb);
}

SEC("cgroup_skb/ingress")
int ingress_connection_tracker(struct __sk_buff *skb)
{
    return handle_packet(skb);
}