// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

#define CONN_POD_ORIGINATED      0
#define CONN_EXTERNAL_ORIGINATED 1

/*
 * Keyed by socket cookie.
 * This is what user space consumes.
 */
struct conn_val {
    __u64 cgroup_id;

    /* canonical tuple */
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;

    /* who initiated the connection */
    __u8  conn_direction;

    /* byte counters */
    __u64 tx_bytes;
    __u64 rx_bytes;

    /* tuple learning state */
    __u8  have_src;
    __u8  have_dst;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, __u64);              /* socket cookie */
    __type(value, struct conn_val);
} conn_map SEC(".maps");

/* ============================================================
 * Helpers
 * ============================================================ */

/* Parse IPv4 + L4 headers and fill tuple */
static __always_inline int parse_ipv4_tuple(struct __sk_buff *skb, struct conn_val *c, __u8 *is_tcp_syn)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *iph = data;
    if ((void *)iph + sizeof(*iph) > data_end)
        return -1;

    if (iph->version != 4)
        return -1;

    c->src_ip = iph->saddr;
    c->dst_ip = iph->daddr;
    c->proto  = iph->protocol;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = data + iph->ihl * 4;
        if ((void *)th + sizeof(*th) > data_end)
            return -1;

        c->src_port = bpf_ntohs(th->source);
        c->dst_port = bpf_ntohs(th->dest);
        *is_tcp_syn = th->syn && !th->ack;
        return 0;
    }

    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *uh = data + iph->ihl * 4;
        if ((void *)uh + sizeof(*uh) > data_end)
            return -1;

        c->src_port = bpf_ntohs(uh->source);
        c->dst_port = bpf_ntohs(uh->dest);
        *is_tcp_syn = 0;
        return 0;
    }

    return -1;
}

/* ============================================================
 * bind4 — learn local (source) tuple for pod-originated
 * ============================================================ */

SEC("cgroup/bind4")
int cg_bind4(struct bpf_sock_addr *ctx)
{
    __u64 cookie = bpf_get_socket_cookie(ctx);

    struct conn_val *c = bpf_map_lookup_elem(&conn_map, &cookie);
    if (!c)
        return 1;

    /* bind4 gives authoritative local tuple */
    if(ctx->user_ip4 != 0) {
        c->src_ip   = ctx->user_ip4;
        c->src_port = bpf_ntohs(ctx->user_port);
        c->have_src = 1;
    }

    return 1;
}

/* ============================================================
 * connect4 — mark pod-originated connections
 * ============================================================ */

SEC("cgroup/connect4")
int cg_connect4(struct bpf_sock_addr *ctx)
{
    __u64 cookie = bpf_get_socket_cookie(ctx);

    struct conn_val c = {};
    c.cgroup_id      = bpf_get_current_cgroup_id();
    c.conn_direction = CONN_POD_ORIGINATED;
    c.proto          = IPPROTO_TCP;

    bpf_map_update_elem(&conn_map, &cookie, &c, BPF_ANY);
    return 1;
}

/* ============================================================
 * ingress skb — RX accounting + external TCP detection
 * ============================================================ */

SEC("cgroup_skb/ingress")
int cg_ingress(struct __sk_buff *skb)
{
    __u64 cookie = bpf_get_socket_cookie(skb);
    struct conn_val *c = bpf_map_lookup_elem(&conn_map, &cookie);

    struct conn_val pkt = {};
    __u8 is_syn = 0;

    if (parse_ipv4_tuple(skb, &pkt, &is_syn) < 0)
        return 1;

    /* External TCP connection: first ingress SYN */
    if (!c && pkt.proto == IPPROTO_TCP && is_syn) {
        pkt.cgroup_id      = bpf_skb_cgroup_id(skb);
        pkt.conn_direction = CONN_EXTERNAL_ORIGINATED;
        pkt.have_src       = 1;
        pkt.have_dst       = 1;

        bpf_map_update_elem(&conn_map, &cookie, &pkt, BPF_ANY);
        c = &pkt;
    }

    /* UDP: learn tuple on first ingress packet */
    if (!c && pkt.proto == IPPROTO_UDP) {
        pkt.cgroup_id      = bpf_skb_cgroup_id(skb);
        pkt.conn_direction = CONN_EXTERNAL_ORIGINATED;
        pkt.have_src       = 1;
        pkt.have_dst       = 1;

        bpf_map_update_elem(&conn_map, &cookie, &pkt, BPF_ANY);
        c = &pkt;
    }

    if (!c)
        return 1;

    /* Learn destination for pod-originated connections */
    if (!c->have_dst) {
        c->dst_ip   = pkt.dst_ip;
        c->dst_port = pkt.dst_port;
        c->have_dst = 1;
    }

    /* Learn source for pod-originated connections */
    if (!c->have_src && c->conn_direction == CONN_POD_ORIGINATED) {
        c->src_ip   = pkt.src_ip;
        c->src_port = pkt.src_port;
        c->have_src = 1;
    }

    __sync_fetch_and_add(&c->rx_bytes, skb->len);
    return 1;
}

/* ============================================================
 * egress skb — TX accounting + tuple completion
 * ============================================================ */

SEC("cgroup_skb/egress")
int cg_egress(struct __sk_buff *skb)
{
    __u64 cookie = bpf_get_socket_cookie(skb);
    struct conn_val *c = bpf_map_lookup_elem(&conn_map, &cookie);
    if (!c)
        return 1;

    struct conn_val pkt = {};
    __u8 is_syn = 0;

    if (parse_ipv4_tuple(skb, &pkt, &is_syn) < 0)
        return 1;

    /* Learn destination for pod-originated TCP/UDP */
    if (!c->have_dst) {
        c->dst_ip   = pkt.dst_ip;
        c->dst_port = pkt.dst_port;
        c->proto    = pkt.proto;
        c->have_dst = 1;
    }

    /* UDP pod-originated without connect/bind */
    if (pkt.proto == IPPROTO_UDP && !c->have_src) {
        c->src_ip   = pkt.src_ip;
        c->src_port = pkt.src_port;
        c->proto    = pkt.proto;
        c->have_src = 1;
    }

    /* Learn source for pod-originated connections */
    if (!c->have_src && c->conn_direction == CONN_POD_ORIGINATED) {
        c->src_ip   = pkt.src_ip;
        c->src_port = pkt.src_port;
        c->have_src = 1;
    }

    __sync_fetch_and_add(&c->tx_bytes, skb->len);
    return 1;
}
