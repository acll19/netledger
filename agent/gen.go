package agent

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -D__KERNEL__ -D__BPF_CORE__" netledger netledger.c
