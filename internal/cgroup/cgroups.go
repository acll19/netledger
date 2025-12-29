package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	v1 "k8s.io/api/core/v1"
)

// GetPodByCgroupID maps a cgroup ID to a pod. Compatible with containerd, crio, and docker (KinD).
func GetPodByCgroupID(cgroupID uint64, pods []*v1.Pod) (*v1.Pod, error) {
	if cgroupID == 0 {
		return nil, fmt.Errorf("invalid cgroup ID: 0")
	}

	cgroupPath, err := getCgroupPathByID(cgroupID)
	if err != nil {
		return nil, fmt.Errorf("cgroup not found: %w", err)
	}

	containerID := extractContainerIDFromPath(cgroupPath)
	if containerID == "" {
		pod := findHostNetworkPod(cgroupPath, pods)
		if pod != nil {
			return pod, nil
		}
		return nil, fmt.Errorf("non-pod cgroup (cgroup path: %s)", cgroupPath)
	}

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

// findHostNetworkPod finds a pod with hostNetwork=true matching the cgroup path.
func findHostNetworkPod(cgroupPath string, pods []*v1.Pod) *v1.Pod {
	for _, pod := range pods {
		if pod.Spec.HostNetwork {
			if matchesHostNetworkPod(cgroupPath, pod) {
				return pod
			}
		}
	}
	return nil
}

// matchesHostNetworkPod checks if a cgroup path matches a hostNetwork pod by pod UID or KinD indicators.
func matchesHostNetworkPod(cgroupPath string, pod *v1.Pod) bool {
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

// getCgroupPathByID finds the cgroup path for a given cgroup ID using stat syscalls.
func getCgroupPathByID(cgroupID uint64) (string, error) {
	cgroupRoot := "/sys/fs/cgroup"

	if cgroupPath, err := findCgroupPathIn(filepath.Join(cgroupRoot, "kubelet.slice"), cgroupID); err == nil {
		return cgroupPath, nil
	}

	// Try system.slice (KinD with docker)
	if cgroupPath, err := findCgroupPathIn(filepath.Join(cgroupRoot, "system.slice"), cgroupID); err == nil {
		return cgroupPath, nil
	}

	if cgroupPath, err := findCgroupPath(cgroupRoot, cgroupID); err == nil {
		return cgroupPath, nil
	}

	return "", fmt.Errorf("cgroup ID %d not found in /sys/fs/cgroup", cgroupID)
}

func findCgroupPathIn(basePath string, cgroupID uint64) (string, error) {
	if _, err := os.Stat(basePath); err != nil {
		return "", fmt.Errorf("base path not found: %w", err)
	}

	return findCgroupPath(basePath, cgroupID)
}

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
		stat, err := os.Stat(fullPath)
		if err != nil {
			continue
		}

		if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
			if sys.Ino == cgroupID {
				return fullPath, nil
			}
		}

		if cgroupPath, err := findCgroupPath(fullPath, cgroupID); err == nil {
			return cgroupPath, nil
		}
	}

	return "", fmt.Errorf("cgroup ID %d not found", cgroupID)
}

// extractContainerIDFromPath extracts container ID from cgroup path, prioritizing cri-* over docker.
func extractContainerIDFromPath(cgroupPath string) string {
	parts := strings.Split(cgroupPath, "/")

	for _, part := range parts {
		if strings.HasPrefix(part, "cri-containerd-") && strings.HasSuffix(part, ".scope") {
			containerID := strings.TrimPrefix(part, "cri-containerd-")
			containerID = strings.TrimSuffix(containerID, ".scope")
			return containerID
		}

		if strings.HasPrefix(part, "cri-crio-") && strings.HasSuffix(part, ".scope") {
			containerID := strings.TrimPrefix(part, "cri-crio-")
			containerID = strings.TrimSuffix(containerID, ".scope")
			return containerID
		}

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

func podContainsContainer(pod *v1.Pod, containerID string) bool {
	for _, container := range pod.Status.ContainerStatuses {
		if containerIDMatch(container.ContainerID, containerID) {
			return true
		}
	}

	for _, container := range pod.Status.InitContainerStatuses {
		if containerIDMatch(container.ContainerID, containerID) {
			return true
		}
	}

	for _, container := range pod.Status.EphemeralContainerStatuses {
		if containerIDMatch(container.ContainerID, containerID) {
			return true
		}
	}

	return false
}

// containerIDMatch compares container IDs, handling "runtime://hash" format.
func containerIDMatch(fullContainerID, containerID string) bool {
	if fullContainerID == "" {
		return false
	}

	parts := strings.Split(fullContainerID, "://")
	if len(parts) == 2 {
		return parts[1] == containerID
	}

	return fullContainerID == containerID
}
