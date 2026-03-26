# NetLedger

NetLedger is an open-source network telemetry system that leverages eBPF (extended Berkeley Packet Filter) to provide fine-grained network flow observation and classification in Kubernetes environments.

## Overview

NetLedger consists of two main components:

- **Agent**: Deployed on each Kubernetes node, the agent uses eBPF programs to capture network flow information at the kernel level, including connection tuples, byte counters, and flow state. It supports both egress and ingress traffic monitoring.
- **Classifier**: Aggregates flow data from agents and performs traffic classification with awareness of Kubernetes metadata (pods, services, namespaces).

## Features

- **eBPF-based Monitoring**: Captures network flows with minimal overhead using kernel-level eBPF programs
- **Kubernetes Integration**: Native awareness of Kubernetes workloads and network policies
- **Connection Tracking**: Monitors TCP and UDP connections across pod boundaries
- **Byte Accounting**: Precise tracking of ingress and egress bytes per connection
- **Flow State Management**: Tracks connection lifecycle including establishment and closure

## Requirements

- Linux kernet v4.10 or above
- Cilium with kube-proxy replacemanent mode on (`cilium-dbg status` should show `KubeProxyReplacement:    True`)

## Building

The project uses eBPF programs compiled with libbpf. Build artifacts are generated from the eBPF source code.

```bash
make build
```

## Deploy

```bash
# TBD
```

## License

NetLedger is licensed under the **Dual MIT/GPL** license. The eBPF programs are specifically licensed under this dual license to ensure compatibility with kernel subsystems that may be licensed under GPL.