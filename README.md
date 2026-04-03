# NetLedger

NetLedger is a network telemetry system that leverages eBPF (extended Berkeley Packet Filter) to provide network flow classification in Kubernetes environments. See the metrics for more details on classification.

## Overview

NetLedger consists of two main components:

- **Agent**: Deployed on each Kubernetes node, the agent uses eBPF programs to capture network flow information at the kernel level, including connection tuples, byte counters, and flow state. It supports both egress and ingress traffic monitoring.
- **Classifier**: Aggregates flow data from agents and performs traffic classification with awareness of Kubernetes metadata (pods, namespaces).

## Features

- **eBPF-based Monitoring**: Captures network flows with minimal overhead using kernel-level eBPF programs
- **Kubernetes Integration**: Native awareness of Kubernetes workloads
- **Connection Tracking**: Monitors TCP and UDP connections across pod boundaries
- **Byte Accounting**: Tracking of ingress and egress bytes per connection

## Requirements

- Linux kernel v4.10 or above.
- Cilium 1.18.4 or above with kube-proxy replacement mode on (`cilium-dbg status` should show `KubeProxyReplacement:    True`).
- Kubernetes 1.27.3 or above
- cgroup v2 enabled in the nodes.

## Limitations

- Only IPv4 traffic is currently supported.
- Only TCP and UDP traffic is currently supported.

## Deploy

Netledger is designed to be deployed on Kubernetes. You can apply the sample manifests in the [deploy](./deploy/) directory. This will create a Deployment named **netledger-classifier** and a DaemonSet named **netledger-agent**. The agent creates a privileged pods.
Feel free to modify the `netledger-classifier-config` ConfigMap according to your needs.

## Metrics

| Metric                                    | Description                                 | Labels                                                               | Unit  |
|-------------------------------------------|---------------------------------------------|----------------------------------------------------------------------|-------|
| netledger_pod_network_egress_bytes_total  | The amount of traffic egressed from the pod | namespace, pod_name, pod_initiated, internet, same_region, same_zone | bytes |
| netledger_pod_network_ingress_bytes_total | The amount of traffic ingressed to the pod  | namespace, pod_name, pod_initiated, internet, same_region, same_zone | bytes |

With the exception of `namespace` and `pod_name`, all labels are boolean.
Note that `pod_initiated=true` means that pod with `<pod_name>` has initiated the request. This is useful for when you want to know the amount of traffic caused by a pod.


## Building

The project uses eBPF programs compiled with libbpf. Build artifacts are generated from the eBPF source code.

```bash
make [-f Makefile.local] build-agent
make [-f Makefile.local] build-classifier
```

## Acknowledgments / Origin

This project is a fork of [polarsignals/kubezonnet](https://github.com/polarsignals/kubezonnet)

Key changes from the original:
- Restructured project layout into
- Added internet classification
- Changed exported metrics name and description
- Replaced netfilter eBPF program with a set of cgroup programs

## License

This project is licensed under the Apache License 2.0 (see the [LICENSE](LICENSE) file for details). The eBPF has a dual license (MIT and GPL).
