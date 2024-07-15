// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

#ifndef __LATENDIST_H_
#define __LATENDIST_H_

#ifdef __BPF_NO_CORE
#include <linux/types.h>
#include "bpf/bpf_compiler.h"
#include <linux/skbuff.h>
#else
#include "vmlinux.h"
#endif

#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_map_helpers.h"
#include "bpf/bpf_bits.h"

#include "if_ether.h"

#define ctx_ptr(ctx, mem) ((void *)(unsigned long) ctx->mem)
char _license[] SEC("license") = "GPL";

struct config {
    __u32 ifindex;
    __u32 dist_latency:1;
    __u32 dist_skblen:1;
    __u32 dist_cpu:1;
    __u32 dist_queue:1;
};

static volatile const struct config CONFIG = {};
#define cfg (&CONFIG)

struct net_tuple {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct net_tuple);
    __type(value, __u64);
    __uint(max_entries, 0x10000);
} timestamps SEC(".maps");

static __always_inline __u64
__get_or_set_ts(struct net_tuple *tuple)
{
    __u64 *ts;

    ts = (typeof(ts)) bpf_map_lookup_and_delete(&timestamps, tuple);
    if (ts)
        return *ts;

    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&timestamps, tuple, &now, BPF_NOEXIST);

    return 0;
}

#define MAX_SLOTS 36

struct hist {
    __u64 slots[MAX_SLOTS];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct hist);
    __uint(max_entries, 2);
} skb_lens SEC(".maps");

static __always_inline void
handle_skb_len(__u32 len, __u32 idx)
{
    if (!cfg->dist_skblen)
        return;

    struct hist *hist = (typeof(hist)) bpf_map_lookup_elem(&skb_lens, &idx);
    if (!hist)
        return;

    __u64 slot = log2l(len);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;

    hist->slots[slot]++; // no need for atomic operation as PERCPU_ARRAY
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} skb_recv_cpus SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} skb_xmit_cpus SEC(".maps");

static __always_inline void
handle_skb_cpu(bool is_rcv)
{
    if (!cfg->dist_cpu)
        return;

    __u64 init = 0;
    __u32 cpu = bpf_get_smp_processor_id();
    void *map = is_rcv ? (void *) &skb_recv_cpus : (void *) &skb_xmit_cpus;
    __u64 *count = (typeof(count)) bpf_map_lookup_or_try_init(map, &cpu, &init);
    if (count)
        __sync_fetch_and_add(count, 1);
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u64);
    __uint(max_entries, 1024);
} skb_queues SEC(".maps");

static __always_inline void
handle_skb_queue(__u16 queue)
{
    if (!cfg->dist_queue)
        return;

    __u64 init = 0;
    __u64 *count = (typeof(count)) bpf_map_lookup_or_try_init(&skb_queues, &queue, &init);
    if (count)
        __sync_fetch_and_add(count, 1);
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct net_tuple);
    __type(value, struct hist);
    __uint(max_entries, 0x800000);
} skb_latencies SEC(".maps");

static __always_inline void
__inc_hist(struct net_tuple *tuple, __u64 prev)
{
    struct hist initial_hist = {};
    struct hist *hist = (typeof(hist)) bpf_map_lookup_or_try_init(&skb_latencies, tuple, &initial_hist);
    if (!hist)
        return;

    __u64 delta = bpf_ktime_get_ns() - prev;
    delta /= 1000; // micro-second

    __u64 slot = log2l(delta);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;

    __sync_fetch_and_add(&hist->slots[slot], 1);
}

static __always_inline void
handle_skb_latency(struct net_tuple *tuple)
{
    if (!cfg->dist_latency)
        return;

    __u64 prev = __get_or_set_ts(tuple);
    if (prev)
        __inc_hist(tuple, prev);
}

#endif // __LATENDIST_H_