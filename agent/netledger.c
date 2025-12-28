// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct ip_key
{
    __u64 cgroup_id;
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
    __u32 _pad;
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
    __uint(max_entries, 65536);
    // The 65536 is suitable for (maybe this value should come from user space)
    // for AKS nodes with 250 pods and 260 active connections each
    // for EKS Standard EC2 (m5.large) nodes and similar pod density as above
    // for GKE 65536 is OK for standard Max. Pods/Nodes (110)

    // for EKS Nitro with Prefix delegation instances maybe use 131072
    // for EKS Network-Optimized (c6in) instances maybe use 262144
    // for GKE High Density configuration (256 pods) maybe use 131072
} ip_map SEC(".maps");

static __always_inline int handle_socket_packet(struct __sk_buff *skb)
{
    // allowed since v4.7+
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *iph = data;
    // MANDATORY: Verifier check to ensure the header is within bounds
    if ((void *)iph + sizeof(struct iphdr) > data_end)
    {
        return 1;
    }

    if (iph->version != 4)
        return 1;

    __u32 saddr = iph->saddr;
    __u32 daddr = iph->daddr;
    __u8 proto = iph->protocol;
    __u8 ihl = iph->ihl * 4;
    // the IHL (Internet Header Length) field specifies the number of
    // 32-bit words in the IPv4 header. Multiplying by 4 converts this value into total bytes.
    // Basically, this is the size of the IP header

    struct ip_key key = {};
    key.cgroup_id = bpf_get_current_cgroup_id();
    key.src_ip = saddr;
    key.dest_ip = daddr;

    if (proto == IPPROTO_TCP)
    {
        struct tcphdr *th = (void *)data + ihl;
        // data + ihl positions at the start of the TCP/UDP header
        // then we can parse ports

        // Bounds check: ensure TCP header fits within packet
        if ((void *)th + sizeof(struct tcphdr) > data_end)
            return 1;
        key.src_port = bpf_ntohs(th->source);
        key.dest_port = bpf_ntohs(th->dest);
    }
    else if (proto == IPPROTO_UDP)
    {
        struct udphdr *uh = (void *)data + ihl;
        // Bounds check: ensure UDP header fits within packet
        if ((void *)uh + sizeof(struct udphdr) > data_end)
            return 1;
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

    return 1;
}

SEC("cgroup_skb/egress")
int egress_connection_tracker(struct __sk_buff *skb)
{
    return handle_socket_packet(skb);
}

SEC("cgroup_skb/ingress")
int ingress_connection_tracker(struct __sk_buff *skb)
{
    return handle_socket_packet(skb);
}