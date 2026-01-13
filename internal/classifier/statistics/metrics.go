package statistics

import "github.com/prometheus/client_golang/prometheus"

type FlowSize struct {
	Traffic uint64
}

type FlowKey struct {
	PodName    string
	Namespace  string
	Internet   bool
	SameZone   bool
	SameRegion bool
}

type StatisticMap = map[FlowKey]FlowSize

type PodKey struct {
	Namespace string
	Name      string
}

var (
	IngressDesc = prometheus.NewDesc(
		"netledger_pod_network_ingress_bytes_total",
		"The amount of traffic ingressed to the pod",
		[]string{"namespace", "pod_name", "internet", "same_region", "same_zone"},
		nil,
	)

	EgressDesc = prometheus.NewDesc(
		"netledger_pod_network_egress_bytes_total",
		"The amount of traffic egressed from the pod",
		[]string{"namespace", "pod_name", "internet", "same_region", "same_zone"},
		nil,
	)
)
