package payload

import (
	"bytes"
	"encoding/json"
)

func Encode(flowEntries Flow) []byte {
	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(flowEntries)
	return buf.Bytes()
}

func Decode(data []byte) (Flow, error) {
	var flow Flow
	err := json.Unmarshal(data, &flow)
	if err != nil {
		return Flow{}, err
	}
	return flow, nil
}

type Flow struct {
	AgentNode   string      `json:"agentNode"`
	StartupTime int64       `json:"timestamp"`
	Entries     []FlowEntry `json:"entries"`
}

type FlowEntry struct {
	SrcIP           string `json:"srcIp"`
	DstIP           string `json:"dstIp"`
	SrcPort         uint16 `json:"srcPort"`
	DstPort         uint16 `json:"dstPort"`
	TxBytes         uint64 `json:"txBytes"`
	RxBytes         uint64 `json:"rxBytes"`
	Direction       int    `json:"direction"`
	SrcPodName      string `json:"srcPodName"`
	SrcPodNamespace string `json:"srcPodNamespace"`
	DstPodName      string `json:"dstPodName"`
	DstPodNamespace string `json:"dstPodNamespace"`
}
