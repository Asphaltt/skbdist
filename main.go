// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jschwinger233/elibpcap"
	flag "github.com/spf13/pflag"
	"golang.org/x/exp/maps"
)

const (
	skbDistLatency = iota
	skbDistSkbLen
	skbDistCpu
	skbDistQueue
)

var (
	runWithNonCore = false
	ifname         string

	distSkbLatency = false
	distSkbLen     = false
	distCpu        = false
	distQueue      = false
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [pcap-filter]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "    Available pcap-filter: see \"man 7 pcap-filter\"\n")
		fmt.Fprintf(os.Stderr, "    Available options:\n")
		flag.PrintDefaults()
	}

	flag.BoolVarP(&runWithNonCore, "non-core", "n", false, "Run with non-core bpf [TODO]")
	flag.StringVarP(&ifname, "interface", "i", "", "Interface to filter packets, all interfaces if not specified")
	flag.BoolVar(&distSkbLatency, "dist-latency", false, "Measure distribution of skb latency")
	flag.BoolVar(&distSkbLen, "dist-skblen", false, "Measure distribution of skb length")
	flag.BoolVar(&distCpu, "dist-cpu", false, "Measure distribution of CPU")
	flag.BoolVar(&distQueue, "dist-queue", false, "Measure distribution of queue")
	flag.Parse()
}

type skbDistConfig struct {
	Ifindex uint32
	Flags   uint32
}

func (c *skbDistConfig) setFlags(set bool, idx int) {
	if set {
		c.Flags |= 1 << uint(idx)
	}
}

func loadSpec() (*ebpf.CollectionSpec, error) {
	btfSpec, _ := btf.LoadKernelSpec()
	supportBtf := btfSpec != nil

	_ = supportBtf
	// if runWithNonCore || !supportBtf {
	// 	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(skbdist))
	// }

	return loadSkbdist()
}

func main() {
	var ifindex uint32
	if ifname != "" {
		ifi, err := net.InterfaceByName(ifname)
		if err != nil {
			log.Fatalf("Failed to get interface %s: %v", ifname, err)
		}

		ifindex = uint32(ifi.Index)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock rlimit: %v", err)
	}

	spec, err := loadSpec()
	if err != nil {
		log.Fatalf("Failed to load BPF collection spec: %v", err)
	}

	var cfg skbDistConfig
	cfg.Ifindex = ifindex
	cfg.setFlags(distSkbLatency, skbDistLatency)
	cfg.setFlags(distSkbLen, skbDistSkbLen)
	cfg.setFlags(distCpu, skbDistCpu)
	cfg.setFlags(distQueue, skbDistQueue)
	if cfg.Flags == 0 {
		cfg.setFlags(true, skbDistLatency)
		cfg.setFlags(true, skbDistSkbLen)
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"CONFIG": cfg,
	}); err != nil {
		log.Fatalf("Failed to rewrite constants: %v", err)
	}

	pcapFilterExpr := strings.Join(flag.Args(), " ")
	if pcapFilterExpr != "" {
		for _, progSpec := range spec.Programs {
			progSpec.Instructions, err = elibpcap.Inject(pcapFilterExpr,
				progSpec.Instructions, elibpcap.Options{
					AtBpf2Bpf:  "filter_pcap_l2",
					DirectRead: false,
					L2Skb:      true,
				})
			if err != nil {
				log.Fatalf("Failed to inject pcap filter expression: %v", err)
			}
		}
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to create BPF collection: %v\n%+v", err, ve)
		}
		log.Fatalf("Failed to create BPF collection: %v", err)
	}
	defer coll.Close()

	defer func() {
		if distSkbLen {
			fmt.Println()
			showSkbLens(coll.Maps["skb_lens"])
			fmt.Println()
		}

		if distCpu {
			fmt.Println()
			showSkbCpus(coll.Maps["skb_recv_cpus"], "Recv")
			fmt.Println()
			showSkbCpus(coll.Maps["skb_xmit_cpus"], "Xmit")
			fmt.Println()
		}

		if distQueue {
			fmt.Println()
			showSkbQueues(coll.Maps["skb_queues"])
			fmt.Println()
		}

		if distSkbLatency {
			fmt.Println()
			showSkbLatencies(coll.Maps["skb_latencies"])
		}
	}()

	if tp, err := link.Tracepoint("net", "netif_receive_skb",
		coll.Programs["tracepoint__netif_receive_skb"], nil); err != nil {
		log.Fatalf("Failed to attach tracepoint/net/netif_receive_skb: %v", err)
	} else {
		log.Println("Attached tracepoint/net/netif_receive_skb")
		defer tp.Close()
	}

	if tp, err := link.Tracepoint("net", "net_dev_xmit",
		coll.Programs["tracepoint__net_dev_xmit"], nil); err != nil {
		log.Fatalf("Failed to attach tracepoint/net/net_dev_xmit: %v", err)
	} else {
		log.Println("Attached tracepoint/net/net_dev_xmit")
		defer tp.Close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Println("Ctrl+C to show results..")

	<-ctx.Done()
}

const (
	maxSlots = 36
)

type slot struct {
	Slots [maxSlots]uint64
}

func (s *slot) sum() uint64 {
	var sum uint64
	for _, v := range s.Slots {
		sum += v
	}
	return sum
}

type tuple struct {
	Saddr [4]byte
	Daddr [4]byte
	Sport [2]byte
	Dport [2]byte
	Proto uint8
	Pad   [3]byte
}

var be = binary.BigEndian

func (t *tuple) String() string {
	var protocol string
	switch t.Proto {
	case 1:
		protocol = "ICMP"
	case 6:
		protocol = "TCP"
	case 17:
		protocol = "UDP"
	default:
		protocol = fmt.Sprintf("Unknown(%d)", t.Proto)
	}

	saddr, daddr := netip.AddrFrom4(t.Saddr), netip.AddrFrom4(t.Daddr)
	sport, dport := be.Uint16(t.Sport[:]), be.Uint16(t.Dport[:])

	return fmt.Sprintf("%s:%d -> %s:%d (%s)", saddr, sport, daddr, dport, protocol)
}

func showSkbLatencies(m *ebpf.Map) {
	compareTuple := func(a, b tuple) int {
		saddrA, saddrB := be.Uint32(a.Saddr[:]), be.Uint32(b.Saddr[:])
		switch {
		case saddrA < saddrB:
			return -1
		case saddrA > saddrB:
			return 1
		}

		daddrA, daddrB := be.Uint32(a.Daddr[:]), be.Uint32(b.Daddr[:])
		switch {
		case daddrA < daddrB:
			return -1
		case daddrA > daddrB:
			return 1
		}

		sportA, sportB := be.Uint16(a.Sport[:]), be.Uint16(b.Sport[:])
		switch {
		case sportA < sportB:
			return -1
		case sportA > sportB:
			return 1
		}

		dportA, dportB := be.Uint16(a.Dport[:]), be.Uint16(b.Dport[:])
		switch {
		case dportA < dportB:
			return -1
		case dportA > dportB:
			return 1
		}

		protoA, protoB := a.Proto, b.Proto
		switch {
		case protoA < protoB:
			return -1
		case protoA > protoB:
			return 1
		}

		return 0
	}

	type kv struct {
		k tuple
		v slot
	}

	compareKv := func(a, b kv) int {
		return compareTuple(a.k, b.k)
	}

	var kvs []kv
	var key tuple
	var val slot

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		kvs = append(kvs, kv{k: key, v: val})
	}

	if err := iter.Err(); err != nil {
		log.Fatalf("Failed to iterate over skb_latencies map: %v", err)
	}

	if len(kvs) == 0 {
		return
	}

	slices.SortFunc(kvs, compareKv)

	for i := range kvs {
		kv := kvs[i]
		fmt.Printf("%s (total %d records) :\n", kv.k.String(), kv.v.sum())
		PrintLog2Hist(kv.v.Slots[:], "µs")
		fmt.Println()
	}
}

func mergeSlots(slots []slot) slot {
	var merged slot
	for _, s := range slots {
		for i := 0; i < maxSlots; i++ {
			merged.Slots[i] += s.Slots[i]
		}
	}
	return merged
}

func showSkbLens(m *ebpf.Map) {
	sendSkbLens := make([]slot, runtime.NumCPU())
	err := m.Lookup(uint32(0), &sendSkbLens)
	if err != nil {
		log.Fatalf("Failed to lookup skb_lens map: %v", err)
	}

	recvSkbLens := make([]slot, runtime.NumCPU())
	err = m.Lookup(uint32(1), &recvSkbLens)
	if err != nil {
		log.Fatalf("Failed to lookup skb_lens map: %v", err)
	}

	merged := mergeSlots(sendSkbLens)
	if sum := merged.sum(); sum > 0 {
		fmt.Printf("Send SKB lengths (total %d pkts) :\n", sum)
		PrintLog2Hist(merged.Slots[:], "byte")

		fmt.Println()
	}

	merged = mergeSlots(recvSkbLens)
	if sum := merged.sum(); sum > 0 {
		fmt.Printf("Receive SKB lengths (total %d pkts) :\n", sum)
		PrintLog2Hist(merged.Slots[:], "byte")
	}
}

func showSkbCpus(m *ebpf.Map, msg string) {
	cpus := make(map[uint32]uint64, 64)

	var key uint32
	var val uint64

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		cpus[key] += val
	}

	if err := iter.Err(); err != nil {
		log.Fatalf("Failed to iterate over skb_cpus map: %v", err)
	}

	keys := maps.Keys(cpus)
	slices.Sort(keys)

	sum := 0
	for _, key := range keys {
		sum += int(cpus[key])
	}

	fmt.Printf("%s CPU's distribution (total %d pkts) :\n", msg, sum)
	for _, key := range keys {
		fmt.Printf("CPU %3d: %d\n", key, cpus[key])
	}
}

func showSkbQueues(m *ebpf.Map) {
	queues := make(map[uint16]uint64, 64)

	var key uint16
	var val uint64

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		queues[key] += val
	}

	if err := iter.Err(); err != nil {
		log.Fatalf("Failed to iterate over skb_queues map: %v", err)
	}

	keys := maps.Keys(queues)
	slices.Sort(keys)

	sum := 0
	for _, key := range keys {
		sum += int(queues[key])
	}

	fmt.Printf("Recv queue distribution (total %d pkts) :\n", sum)
	for _, key := range keys {
		fmt.Printf("Queue %3d: %d\n", key, queues[key])
	}
}
