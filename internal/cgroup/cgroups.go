package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	v1 "k8s.io/api/core/v1"
)

// GetPodByCgroupID returns the pod that corresponds to the given cgroup ID.
// It traverses the cgroup filesystem and uses stat syscalls to get actual cgroup IDs,
// then matches them against the container IDs from the pod list.
// This function is compatible with:
// - containerd and crio in standard Kubernetes clusters
// - docker in KinD (Kubernetes in Docker)
// Returns error if:
// - cgroup ID not found in filesystem (likely root/init process)
// - cgroup path is host/node network traffic that doesn't belong to any pod (system services, kubelet, user processes)
// - container ID extracted doesn't match any pod in the list
func GetPodByCgroupID(cgroupID uint64, pods []*v1.Pod) (*v1.Pod, error) {
	if cgroupID == 0 {
		return nil, fmt.Errorf("invalid cgroup ID: 0")
	}

	// Get the cgroup path from the cgroup ID by traversing the filesystem
	cgroupPath, err := getCgroupPathByID(cgroupID)
	if err != nil {
		// cgroup ID 1 typically represents init/root process, not associated with any pod
		return nil, fmt.Errorf("cgroup not found: %w", err)
	}

	// Extract container ID from the cgroup path
	containerID := extractContainerIDFromPath(cgroupPath)
	if containerID == "" {
		// No container ID found in path - this is host/system traffic
		// Check if this cgroup belongs to any pod with hostNetwork=true
		pod := findHostNetworkPod(cgroupPath, pods)
		if pod != nil {
			return pod, nil
		}
		return nil, fmt.Errorf("non-pod cgroup (cgroup path: %s)", cgroupPath)
	}

	// Match the container ID against pods
	for _, pod := range pods {
		if podContainsContainer(pod, containerID) {
			return pod, nil
		}
	}

	// Container ID not found in any pod - could be a hostNetwork pod
	// or an unknown/deleted pod
	pod := findHostNetworkPod(cgroupPath, pods)
	if pod != nil {
		return pod, nil
	}

	return nil, fmt.Errorf("unknown container: %s", containerID)
}

// findHostNetworkPod searches for a pod with hostNetwork=true that might match the cgroup path.
// This handles traffic from pods using the host network namespace.
func findHostNetworkPod(cgroupPath string, pods []*v1.Pod) *v1.Pod {
	for _, pod := range pods {
		if pod.Spec.HostNetwork {
			// For hostNetwork pods, we can try to match by pod UID in the cgroup path
			// or by finding the docker/kubelet container associated with this pod
			if matchesHostNetworkPod(cgroupPath, pod) {
				return pod
			}
		}
	}
	return nil
}

// matchesHostNetworkPod checks if a cgroup path could belong to a hostNetwork pod.
// Since hostNetwork pods share the host's cgroups, we look for pod-specific identifiers.
func matchesHostNetworkPod(cgroupPath string, pod *v1.Pod) bool {
	// Try to match pod UID in the cgroup path
	// Pod UIDs appear in paths like: kubelet-kubepods-burstable-pod<UID>.slice
	podUID := string(pod.UID)
	if strings.Contains(cgroupPath, podUID) {
		return true
	}

	// For KinD with docker, check if the docker container is in the path and has kubelet cgroups
	// This indicates a pod running in KinD
	if strings.Contains(cgroupPath, "docker-") && strings.Contains(cgroupPath, "kubelet.slice") {
		return true
	}

	return false
}

// getCgroupPathByID reads the cgroup filesystem and uses stat syscalls to find the path for a given cgroup ID.
// It searches through /sys/fs/cgroup recursively, calling stat on each directory to get its cgroup ID.
// Supports multiple Kubernetes setups:
// - Standard K8s: /sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod<UID>.slice/cri-containerd-<containerID>.scope/
// - KinD (docker): /sys/fs/cgroup/system.slice/docker-<containerID>.scope/
func getCgroupPathByID(cgroupID uint64) (string, error) {
	cgroupRoot := "/sys/fs/cgroup"

	// Try kubelet.slice first (standard K8s clusters with containerd/crio)
	if cgroupPath, err := findCgroupPathIn(filepath.Join(cgroupRoot, "kubelet.slice"), cgroupID); err == nil {
		return cgroupPath, nil
	}

	// Try system.slice (KinD with docker)
	if cgroupPath, err := findCgroupPathIn(filepath.Join(cgroupRoot, "system.slice"), cgroupID); err == nil {
		return cgroupPath, nil
	}

	// Fallback: search entire cgroup root
	if cgroupPath, err := findCgroupPath(cgroupRoot, cgroupID); err == nil {
		return cgroupPath, nil
	}

	return "", fmt.Errorf("cgroup ID %d not found in /sys/fs/cgroup", cgroupID)
}

// findCgroupPathIn searches for a cgroup ID starting from a specific directory.
func findCgroupPathIn(basePath string, cgroupID uint64) (string, error) {
	// Check if the base path exists first
	if _, err := os.Stat(basePath); err != nil {
		return "", fmt.Errorf("base path not found: %w", err)
	}

	return findCgroupPath(basePath, cgroupID)
}

// findCgroupPath recursively searches for a cgroup directory matching the given ID using stat syscalls.
func findCgroupPath(basePath string, cgroupID uint64) (string, error) {
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return "", fmt.Errorf("reading directory %s: %w", basePath, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		fullPath := filepath.Join(basePath, entry.Name())

		// Use stat to get the actual cgroup ID of this directory
		stat, err := os.Stat(fullPath)
		if err != nil {
			continue
		}

		// Extract cgroup ID from stat info using Ino field
		if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
			if sys.Ino == cgroupID {
				return fullPath, nil
			}
		}

		// Recursively search subdirectories
		if cgroupPath, err := findCgroupPath(fullPath, cgroupID); err == nil {
			return cgroupPath, nil
		}
	}

	return "", fmt.Errorf("cgroup ID %d not found", cgroupID)
}

// extractContainerIDFromPath extracts the container ID from a cgroup path.
// Prioritizes container runtime IDs (cri-containerd, cri-crio) over docker IDs,
// since the docker ID is just the wrapper container in KinD, not the actual pod container.
// Supports multiple runtime formats:
// - Kubernetes with containerd: cri-containerd-<container_id>.scope
// - Kubernetes with crio: cri-crio-<container_id>.scope
// - KinD with docker: docker-<full_container_hash>.scope (fallback, not a pod container)
func extractContainerIDFromPath(cgroupPath string) string {
	parts := strings.Split(cgroupPath, "/")

	// First pass: look for Kubernetes container runtime IDs (cri-containerd, cri-crio)
	// These are the actual pod containers, not wrapper containers
	for _, part := range parts {
		// Kubernetes with containerd: cri-containerd-<id>.scope
		if strings.HasPrefix(part, "cri-containerd-") && strings.HasSuffix(part, ".scope") {
			containerID := strings.TrimPrefix(part, "cri-containerd-")
			containerID = strings.TrimSuffix(containerID, ".scope")
			return containerID
		}

		// Kubernetes with crio: cri-crio-<id>.scope
		if strings.HasPrefix(part, "cri-crio-") && strings.HasSuffix(part, ".scope") {
			containerID := strings.TrimPrefix(part, "cri-crio-")
			containerID = strings.TrimSuffix(containerID, ".scope")
			return containerID
		}

		// Legacy crio format: crio-<container_id>
		if strings.HasPrefix(part, "crio-") && strings.HasSuffix(part, ".scope") {
			containerID := strings.TrimPrefix(part, "crio-")
			containerID = strings.TrimSuffix(containerID, ".scope")
			return containerID
		}
	}

	// Second pass: look for docker (KinD wrapper container)
	// Only return docker ID if no cri-* container was found
	for _, part := range parts {
		if strings.HasPrefix(part, "docker-") && strings.HasSuffix(part, ".scope") {
			containerID := strings.TrimPrefix(part, "docker-")
			containerID = strings.TrimSuffix(containerID, ".scope")
			return containerID
		}
	}

	return ""
}

// podContainsContainer checks if any container in the pod matches the given container ID.
func podContainsContainer(pod *v1.Pod, containerID string) bool {
	// Check regular containers
	for _, container := range pod.Status.ContainerStatuses {
		if containerIDMatch(container.ContainerID, containerID) {
			return true
		}
	}

	// Check init containers
	for _, container := range pod.Status.InitContainerStatuses {
		if containerIDMatch(container.ContainerID, containerID) {
			return true
		}
	}

	// Check ephemeral containers
	for _, container := range pod.Status.EphemeralContainerStatuses {
		if containerIDMatch(container.ContainerID, containerID) {
			return true
		}
	}

	return false
}

// containerIDMatch checks if the full container ID matches the given ID.
// The containerID format is "runtime://hash", so we extract the hash and compare.
func containerIDMatch(fullContainerID, containerID string) bool {
	if fullContainerID == "" {
		return false
	}

	// Extract the hash from "containerd://hash" or "crio://hash"
	parts := strings.Split(fullContainerID, "://")
	if len(parts) == 2 {
		return parts[1] == containerID
	}

	return fullContainerID == containerID
}
