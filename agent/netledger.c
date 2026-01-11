// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

struct ip_key
{
    __u64 cgroup_id;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 direction; // 0 = egress, 1 = ingress
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

static __always_inline int handle_socket_packet_ipv4(struct __sk_buff *skb, __u8 direction)
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
    key.cgroup_id = bpf_skb_cgroup_id(skb);
    key.src_ip = saddr;
    key.dst_ip = daddr;
    key.direction = direction;

    if (proto == IPPROTO_TCP)
    {
        struct tcphdr *th = (void *)data + ihl;
        // data + ihl positions at the start of the TCP/UDP header
        // then we can parse ports

        // Bounds check: ensure TCP header fits within packet
        if ((void *)th + sizeof(struct tcphdr) > data_end)
            return 1;
        key.src_port = bpf_ntohs(th->source);
        key.dst_port = bpf_ntohs(th->dest);
    }
    else if (proto == IPPROTO_UDP)
    {
        struct udphdr *uh = (void *)data + ihl;
        // Bounds check: ensure UDP header fits within packet
        if ((void *)uh + sizeof(struct udphdr) > data_end)
            return 1;
        key.src_port = bpf_ntohs(uh->source);
        key.dst_port = bpf_ntohs(uh->dest);
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
    return handle_socket_packet_ipv4(skb, 0); // 0 = egress
}

SEC("cgroup_skb/ingress")
int ingress_connection_tracker(struct __sk_buff *skb)
{
    return handle_socket_packet_ipv4(skb, 1); // 1 = ingress
}

SEC("tcx/egress")
int egress_tcx_connection_tracker(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    if (iph->version != 4)
        return TC_ACT_OK;

    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph))
        return TC_ACT_OK;

    if ((void *)iph + ip_hdr_len > data_end)
        return TC_ACT_OK;

    if (iph->protocol != IPPROTO_TCP &&
        iph->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    __u16 src_port = 0;
    __u16 dst_port = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + ip_hdr_len;
        if ((void *)(tcph + 1) > data_end)
            return TC_ACT_OK;

        src_port = bpf_ntohs(tcph->source);
        dst_port = bpf_ntohs(tcph->dest);
    } else {
        struct udphdr *udph = (void *)iph + ip_hdr_len;
        if ((void *)(udph + 1) > data_end)
            return TC_ACT_OK;

        src_port = bpf_ntohs(udph->source);
        dst_port = bpf_ntohs(udph->dest);
    }

    struct ip_key key = {};
    key.cgroup_id = bpf_get_current_cgroup_id();
    key.src_ip    = iph->saddr;
    key.dst_ip    = iph->daddr;
    key.src_port  = src_port;
    key.dst_port  = dst_port;
    key.direction = 0; /* egress */

    struct ip_value *val = bpf_map_lookup_elem(&ip_map, &key);
    if (val) {
        __sync_fetch_and_add(&val->packet_size, skb->len);
    } else {
        struct ip_value new_val = {
            .packet_size = skb->len,
        };
        bpf_map_update_elem(&ip_map, &key, &new_val, BPF_ANY);
    }

    return TC_ACT_OK;
}
