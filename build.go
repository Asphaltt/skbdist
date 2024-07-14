// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import _ "embed"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang skbdist ./bpf/skbdist_core.c -- -I./bpf/headers -Wall -D__TARGET_ARCH_x86

// //go:generate echo "clang -O2 -target bpf -c ./bpf/skbdist.c -I./bpf/headers -Wall -D__TARGET_ARCH_x86 -D__BPF_NO_CORE -o ./bpf/skbdist.o"
// //go:generate clang -O2 -target bpf -c ./bpf/skbdist.c -I./bpf/headers -Wall -D__TARGET_ARCH_x86 -D__BPF_NO_CORE -o ./bpf/skbdist.o

// //go:embed bpf/skbdist.o
// var skbdist []byte
