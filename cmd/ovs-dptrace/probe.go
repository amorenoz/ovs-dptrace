package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go probe bpf/probe.c -- -D__TARGET_ARCH_x86
