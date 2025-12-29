package payload

import (
	"bytes"
	"encoding/json"
)

// Key for the eBPF map representing IP pairs
type IPKey struct {
	Cgroupid  uint64
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	Direction uint8 // 0 = egress, 1 = ingress
	_         [3]byte
}

// Value for the eBPF map representing total packet sizes
type IPValue struct {
	PacketSize uint64
}

func Encode(flowEntries []FlowEntry) []byte {
	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(flowEntries)
	return buf.Bytes()
}

type FlowEntry struct {
	SrcIP     string `json:"srcIp"`
	DstIP     string `json:"dstIp"`
	SrcPort   uint16 `json:"srcPort"`
	DstPort   uint16 `json:"dstPort"`
	Traffic   uint64 `json:"traffic"`
	Direction string `json:"direction"`
}
