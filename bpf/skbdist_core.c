/**
 * Copyright 2024 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "skbdist.h"

static __noinline bool
filter_pcap_l2(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
{
    return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline bool
filter(struct sk_buff *skb)
{
    int ifindex = BPF_CORE_READ(skb, dev, ifindex);
    if (cfg->ifindex && ifindex != cfg->ifindex)
        return false;

    void *skb_head = BPF_CORE_READ(skb, head);
    void *data = skb_head + BPF_CORE_READ(skb, mac_header);
    void *data_end = skb_head + BPF_CORE_READ(skb, tail);
    return filter_pcap_l2(skb, skb, skb, data, data_end);
}

static __always_inline bool
set_tuple(struct iphdr *iph, struct net_tuple *tuple)
{
    struct udphdr *udph;
    int ihl;

    BPF_CORE_READ_INTO(&tuple->saddr, iph, saddr);
    BPF_CORE_READ_INTO(&tuple->daddr, iph, daddr);
    BPF_CORE_READ_INTO(&tuple->proto, iph, protocol);

    switch (BPF_CORE_READ(iph, protocol)) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        ihl = BPF_CORE_READ_BITFIELD_PROBED(iph, ihl) << 2;
        udph = (typeof(udph)) (((void *) iph) + ihl);
        BPF_CORE_READ_INTO(&tuple->sport, udph, source);
        BPF_CORE_READ_INTO(&tuple->dport, udph, dest);
        return true;

    case IPPROTO_ICMP:
        tuple->sport = 0;
        tuple->dport = 0;
        return true;

    default:
        return false;
    }
}

static __always_inline bool
extract_tuple(struct sk_buff *skb, struct net_tuple *tuple)
{
    void *skb_head = BPF_CORE_READ(skb, head);
    struct ethhdr *eth = (typeof(eth)) (skb_head + BPF_CORE_READ(skb, mac_header));

    struct iphdr *iph = (typeof(iph)) (eth + 1);
    if (BPF_CORE_READ(eth, h_proto) == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = (typeof(vlan)) (eth + 1);
        if (BPF_CORE_READ(vlan, h_vlan_encapsulated_proto) != bpf_htons(ETH_P_IP))
            return false;

        iph = (typeof(iph)) (vlan + 1);

    } else if (BPF_CORE_READ(eth, h_proto) != bpf_htons(ETH_P_IP)) {
        return false;
    }

    if (BPF_CORE_READ_BITFIELD_PROBED(iph, version) != 4)
        return false;

    return set_tuple(iph, tuple);
}

static __always_inline int
handle_skb(struct sk_buff *skb, const bool is_rcv)
{
    if (!filter(skb))
        return BPF_OK;

    struct net_tuple tuple = {};
    if (!extract_tuple(skb, &tuple))
        return BPF_OK;

    if (is_rcv) {
        __be32 addr = tuple.saddr;
        tuple.saddr = tuple.daddr;
        tuple.daddr = addr;

        __be16 port = tuple.sport;
        tuple.sport = tuple.dport;
        tuple.dport = port;
    }

    handle_skb_latency(&tuple);

    int len = BPF_CORE_READ(skb, len);
    handle_skb_len(len, is_rcv);

    if (is_rcv) {
        __u16 queue = BPF_CORE_READ(skb, queue_mapping);
        handle_skb_queue(queue);
    }

    handle_skb_cpu(is_rcv);

    return BPF_OK;
}

struct tp_netif_receive_skb_args {
    __u64 unused;

    void * skbaddr;
    unsigned int len;
};

SEC("tracepoint/net/netif_receive_skb")
int tracepoint__netif_receive_skb(struct tp_netif_receive_skb_args *args)
{
    return handle_skb((struct sk_buff *) args->skbaddr, true);
}

struct tp_net_dev_xmit_args {
    __u64 unused;

    void * skbaddr;
    unsigned int len;
    int rc;
};

SEC("tracepoint/net/net_dev_xmit")
int tracepoint__net_dev_xmit(struct tp_net_dev_xmit_args *args)
{
    return handle_skb((struct sk_buff *) args->skbaddr, false);
}
