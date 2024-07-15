<!--
 Copyright 2024 Leon Hwang.
 SPDX-License-Identifier: Apache-2.0
-->

# skbdist: A bpf-based packet's latency distribution measurement tool

At netdev layer of Linux networking stack, there are two tracepoints to measure packet's latency:

- `netif_receive_skb`: This tracepoint is triggered when a packet is received by the network device driver.
- `net_dev_xmit`: This tracepoint is triggered when a packet is transmitted by the network device driver.

## Usage

```bash
$ ./skbdist -h
Usage: ./skbdist [options] [pcap-filter]
    Available pcap-filter: see "man 7 pcap-filter"
    Available options:
      --dist-cpu           Measure distribution of CPU
      --dist-latency       Measure distribution of skb latency
      --dist-queue         Measure distribution of queue
      --dist-skblen        Measure distribution of skb length
  -i, --interface string   Interface to filter packets, all interfaces if not specified
  -n, --non-core           Run with non-core bpf [TODO]
```

NOTE: If to use [pcap-filter](https://www.tcpdump.org/manpages/pcap-filter.7.html), `src`/`dst` should not be used in it.

## Examples

To measure the response latency of a TCP port, you can use the following command:

```bash
$ sudo ./skbdist --dist-cpu --dist-queue --dist-skblen --dist-latency tcp port 8080
2024/07/15 13:41:27 Attached tracepoint/net/netif_receive_skb
2024/07/15 13:41:27 Attached tracepoint/net/net_dev_xmit
Ctrl+C to show results..
^C
Send SKB lengths (total 5 pkts) :
      byte               : count         distribution
         0 -> 1          : 0             |                                        |
         2 -> 3          : 0             |                                        |
         4 -> 7          : 0             |                                        |
         8 -> 15         : 0             |                                        |
        16 -> 31         : 0             |                                        |
        32 -> 63         : 0             |                                        |
        64 -> 127        : 3             |****************************************|
       128 -> 255        : 1             |*************                           |
       256 -> 511        : 0             |                                        |
       512 -> 1023       : 1             |*************                           |

Receive SKB lengths (total 6 pkts) :
      byte               : count         distribution
         0 -> 1          : 0             |                                        |
         2 -> 3          : 0             |                                        |
         4 -> 7          : 0             |                                        |
         8 -> 15         : 0             |                                        |
        16 -> 31         : 0             |                                        |
        32 -> 63         : 4             |****************************************|
        64 -> 127        : 1             |**********                              |
       128 -> 255        : 1             |**********                              |


Recv CPU's distribution (total 6 pkts) :
CPU   6: 6

Xmit CPU's distribution (total 5 pkts) :
CPU   3: 2
CPU   6: 3


Recv queue distribution (total 6 pkts) :
Queue   0: 6


192.168.241.133:8080 -> 192.168.241.1:61645 (TCP) (total 5 records) :
        µs               : count         distribution
         0 -> 1          : 0             |                                        |
         2 -> 3          : 1             |****************************************|
         4 -> 7          : 0             |                                        |
         8 -> 15         : 1             |****************************************|
        16 -> 31         : 0             |                                        |
        32 -> 63         : 0             |                                        |
        64 -> 127        : 1             |****************************************|
       128 -> 255        : 1             |****************************************|
       256 -> 511        : 0             |                                        |
       512 -> 1023       : 0             |                                        |
      1024 -> 2047       : 0             |                                        |
      2048 -> 4095       : 0             |                                        |
      4096 -> 8191       : 0             |                                        |
      8192 -> 16383      : 1             |****************************************|
```

## Development

`skbdist` requires the following dependencies:

- `clang` and `llvm`: To compile eBPF program.
- `libpcap.a`: To inject pcap-filter to eBPF program.

Build and run:

```bash
go generate
go build -v
./skbdist -h
```

## TODOs

- [ ] Support non-CORE bpf on old kernels
- [ ] Support filtering inner-VxLAN packets

## Credits

- [elibpcap](github.com/jschwinger233/elibpcap): A really cool library to inject pcap-filter into eBPF programs.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
