package bpf

//go:generate go tool github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -D__KERNEL__ -D__BPF_CORE__" NetLedger ../../../bpf/netledger.c
