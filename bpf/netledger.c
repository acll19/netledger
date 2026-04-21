// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef BPF_SOCK_OPS_TCP_ACK_CB
#define BPF_SOCK_OPS_TCP_ACK_CB 14
#endif

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

#define EGRESS 0
#define INGRESS 1

#define IS_TCP_RST 1
#define IS_TCP_FIN 2

#define CONN_POD_INITIATED 1
#define CONN_EXT_INITIATED 0

struct conn_tuple
{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
};

struct conn_stats
{
    __u64 cgroup_id;
    __u64 tx_bytes;
    __u64 rx_bytes;

    __u32 src_ip4;
    __u32 dst_ip4;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;

    /*
      0 EGRESS, 1 INGRESS
    */
    __u8 conn_direction;
    /*
        Whether or not the pod initated this request
        We duplicate here to avoid having to read this from meta in user space
    */
    __u8 pod_initiated;
};

struct conn_meta
{
    __u64 cgroup_id;
    /* is updated every time a packet of this connection is seen
       useful for LRU logic where hot connections are less likely to be evicted.
       also opens the doors to introduce TTL eviction if needed.
     */
    __u64 last_seen;
    /* use to populate same field in stats for active connections */
    __u8 pod_initiated;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144); /* 256K entries ~ 16MB */
    __type(key, __u64);          // socket cookie
    __type(value, struct conn_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} conn_stats SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144); /* 256K entries ~ 16MB */
    __type(key, __u64);          // socket cookie
    __type(value, struct conn_meta);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} conn_meta SEC(".maps");

/* ============================================================
 * Helpers
 * ============================================================ */

/* Parse IPv4 + L4 headers and fill tuple.
   Returns 0 on success, -1 on failure */
static __always_inline int
parse_ipv4_tuple(struct __sk_buff *skb,
                 struct conn_tuple *pkt,
                 __u8 *tcp_state)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    void *cursor = data;

    /* Optional Ethernet header */
    struct ethhdr *eth = cursor;
    if ((void *)eth + sizeof(*eth) <= data_end)
    {
        /* ETH_P_IP is big-endian on the wire */
        if (eth->h_proto == bpf_htons(ETH_P_IP))
        {
            cursor += sizeof(*eth);
        }
    }

    /* IPv4 header */
    struct iphdr *iph = cursor;
    if ((void *)iph + sizeof(*iph) > data_end)
        return -1;

    if (iph->version != 4)
        return -1;

    pkt->src_ip = iph->saddr;
    pkt->dst_ip = iph->daddr;
    pkt->proto = iph->protocol;

    cursor += iph->ihl * 4;
    if (cursor > data_end)
        return -1;

    /* TCP */
    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *th = cursor;
        if ((void *)th + sizeof(*th) > data_end)
            return -1;

        pkt->src_port = bpf_ntohs(th->source);
        pkt->dst_port = bpf_ntohs(th->dest);
        if (th->syn && !th->ack)
            *tcp_state = IS_TCP_FST_PKT_SYN;
        else if (th->rst)
            *tcp_state = IS_TCP_RST;
        else if (th->fin)
            *tcp_state = IS_TCP_FIN;
        return 0;
    }

    /* UDP */
    if (iph->protocol == IPPROTO_UDP)
    {
        struct udphdr *uh = cursor;
        if ((void *)uh + sizeof(*uh) > data_end)
            return -1;

        pkt->src_port = bpf_ntohs(uh->source);
        pkt->dst_port = bpf_ntohs(uh->dest);
        *tcp_state = 0;
        return 0;
    }

    return -1;
}

/* ==========================================
 * sock_ops - learn established TCP connections
    + cleanup on close
 * ========================================== */
SEC("sockops")
int tcp_sockops(struct bpf_sock_ops *skops)
{
    bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);

    /* Only care about TCP IPv4 for now */
    if (skops->family != AF_INET)
        return 0;

    __u64 cookie = bpf_get_socket_cookie(skops);
    if (!cookie)
        return 0;

    switch (skops->op)
    {
    case BPF_SOCK_OPS_STATE_CB:
    {
        if (skops->args[1] == BPF_TCP_CLOSE)
        {
            bpf_map_delete_elem(&conn_meta, &cookie);
        }
        break;
    }

    default:
        break;
    }

    return 1;
}

SEC("cgroup/connect4")
int cg_connect4(struct bpf_sock_addr *ctx)
{
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct conn_meta *meta = bpf_map_lookup_elem(&conn_meta, &cookie);

    if (!meta)
    {
        __u64 cgroup_id = bpf_get_current_cgroup_id();
        struct conn_meta new_meta =
            {
                .cgroup_id = cgroup_id,
                .pod_initiated = CONN_POD_INITIATED,
                .last_seen = bpf_ktime_get_ns(),
            };
        bpf_map_update_elem(&conn_meta, &cookie, &new_meta, BPF_ANY);
    }
    return 1;
}

/* ============================================================
 * ingress skb — RX accounting + external TCP detection
 * ============================================================ */
SEC("cgroup_skb/ingress")
int cg_ingress(struct __sk_buff *skb)
{
    __u64 cookie = bpf_get_socket_cookie(skb);
    if (!cookie)
        return 0;

    struct conn_tuple pkt = {};
    __u8 tcp_state = 0;

    if (parse_ipv4_tuple(skb, &pkt, &tcp_state) < 0)
        return 1;

    if (pkt.proto != IPPROTO_TCP && pkt.proto != IPPROTO_UDP)
        return 1; // Non-TCP/UDP, skip

    struct conn_stats *stats = bpf_map_lookup_elem(&conn_stats, &cookie);
    struct conn_meta *meta = bpf_map_lookup_elem(&conn_meta, &cookie);

    if (pkt.proto == IPPROTO_TCP)
    {
        if (tcp_state == IS_TCP_RST || tcp_state == IS_TCP_FIN)
        {
            if (meta && !stats)
            {
                meta->last_seen = bpf_ktime_get_ns();
                bpf_map_update_elem(&conn_meta, &cookie, meta, BPF_EXIST);

                struct conn_stats new_stats = {
                    .cgroup_id = meta->cgroup_id,
                    .src_ip4 = pkt.src_ip,
                    .dst_ip4 = pkt.dst_ip,
                    .src_port = pkt.src_port,
                    .dst_port = pkt.dst_port,
                    .proto = pkt.proto,
                    .conn_direction = INGRESS,
                    .pod_initiated = meta->pod_initiated,
                    .rx_bytes = skb->len,
                };
                bpf_map_update_elem(&conn_stats, &cookie, &new_stats, BPF_ANY);
            }
            else if (meta && stats)
                __sync_fetch_and_add(&stats->rx_bytes, skb->len);

            bpf_map_delete_elem(&conn_meta, &cookie);
            return 1;
        }
        else if (meta && !stats)
        {
            meta->last_seen = bpf_ktime_get_ns();
            bpf_map_update_elem(&conn_meta, &cookie, meta, BPF_EXIST);

            struct conn_stats new_stats = {
                .cgroup_id = meta->cgroup_id,
                .src_ip4 = pkt.src_ip,
                .dst_ip4 = pkt.dst_ip,
                .src_port = pkt.src_port,
                .dst_port = pkt.dst_port,
                .proto = pkt.proto,
                .conn_direction = INGRESS,
                .pod_initiated = meta->pod_initiated,
                .rx_bytes = skb->len,
            };
            bpf_map_update_elem(&conn_stats, &cookie, &new_stats, BPF_ANY);

            return 1;
        }
        else
        {
            stats = bpf_map_lookup_elem(&conn_stats, &cookie);
            if (stats)
                __sync_fetch_and_add(&stats->rx_bytes, skb->len);
            return 1;
        }
    }

    if (pkt.proto == IPPROTO_UDP)
    {
        // currently not possible to know which if pod initiated.
        // maybe based on first packet seen?
        if (!stats)
        {
            __u64 cgroup_id = bpf_get_current_cgroup_id();
            struct conn_stats new_stats = {
                .cgroup_id = cgroup_id,
                .src_ip4 = pkt.src_ip,
                .dst_ip4 = pkt.dst_ip,
                .src_port = pkt.src_port,
                .dst_port = pkt.dst_port,
                .proto = pkt.proto,
                .conn_direction = INGRESS,
                .pod_initiated = CONN_EXT_INITIATED,
                .rx_bytes = skb->len,
            };
            bpf_map_update_elem(&conn_stats, &cookie, &new_stats, BPF_ANY);
        }
        else if (stats)
            __sync_fetch_and_add(&stats->rx_bytes, skb->len);
        return 1;
    }

    return 1;
}

/* ============================================================
 * egress skb — TX accounting + tuple completion
 * ============================================================ */
SEC("cgroup_skb/egress")
int cg_egress(struct __sk_buff *skb)
{
    __u64 cookie = bpf_get_socket_cookie(skb);
    if (!cookie)
        return 0;

    struct conn_tuple pkt = {};
    __u8 tcp_state = 0;

    if (parse_ipv4_tuple(skb, &pkt, &tcp_state) < 0)
        return 1;

    if (pkt.proto != IPPROTO_TCP && pkt.proto != IPPROTO_UDP)
        return 1; // Non-TCP/UDP, skip

    struct conn_stats *stats = bpf_map_lookup_elem(&conn_stats, &cookie);
    struct conn_meta *meta = bpf_map_lookup_elem(&conn_meta, &cookie);

    if (pkt.proto == IPPROTO_TCP)
    {
        if (tcp_state == IS_TCP_RST || tcp_state == IS_TCP_FIN)
        {
            if (meta && !stats)
            {
                meta->last_seen = bpf_ktime_get_ns();
                bpf_map_update_elem(&conn_meta, &cookie, meta, BPF_EXIST);

                struct conn_stats new_stats = {
                    .cgroup_id = meta->cgroup_id,
                    .src_ip4 = pkt.src_ip,
                    .dst_ip4 = pkt.dst_ip,
                    .src_port = pkt.src_port,
                    .dst_port = pkt.dst_port,
                    .proto = pkt.proto,
                    .conn_direction = EGRESS,
                    .pod_initiated = meta->pod_initiated,
                    .tx_bytes = skb->len,
                };
                bpf_map_update_elem(&conn_stats, &cookie, &new_stats, BPF_ANY);
            }
            else if (meta && stats)
                __sync_fetch_and_add(&stats->tx_bytes, skb->len);

            bpf_map_delete_elem(&conn_meta, &cookie);

            return 1;
        }
        else if (meta && !stats)
        {
            meta->last_seen = bpf_ktime_get_ns();
            bpf_map_update_elem(&conn_meta, &cookie, meta, BPF_EXIST);

            struct conn_stats new_stats = {
                .cgroup_id = meta->cgroup_id,
                .src_ip4 = pkt.src_ip,
                .dst_ip4 = pkt.dst_ip,
                .src_port = pkt.src_port,
                .dst_port = pkt.dst_port,
                .proto = pkt.proto,
                .conn_direction = EGRESS,
                .pod_initiated = meta->pod_initiated,
                .tx_bytes = skb->len,
            };
            bpf_map_update_elem(&conn_stats, &cookie, &new_stats, BPF_ANY);

            return 1;
        }
        else
        {
            stats = bpf_map_lookup_elem(&conn_stats, &cookie);
            if (stats)
                __sync_fetch_and_add(&stats->tx_bytes, skb->len);
            return 1;
        }
    }

    if (pkt.proto == IPPROTO_UDP)
    {
        // We do not care about connection state, so we just count bytes in stats
        if (!stats)
        {
            __u64 cgroup_id = bpf_get_current_cgroup_id();
            struct conn_stats new_stats = {
                .cgroup_id = cgroup_id,
                .src_ip4 = pkt.src_ip,
                .dst_ip4 = pkt.dst_ip,
                .src_port = pkt.src_port,
                .dst_port = pkt.dst_port,
                .proto = pkt.proto,
                .conn_direction = EGRESS,
                .pod_initiated = CONN_POD_INITIATED, /* limitation: what if this is a response packet actually? */
                .tx_bytes = skb->len,
            };
            bpf_map_update_elem(&conn_stats, &cookie, &new_stats, BPF_ANY);
            stats = bpf_map_lookup_elem(&conn_stats, &cookie);
        }
        else if (stats)
            __sync_fetch_and_add(&stats->tx_bytes, skb->len);
        return 1;
    }

    return 1;
}
