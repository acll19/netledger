package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/acll19/netledger/internal/agent/kubernetes"
	v1 "k8s.io/api/core/v1"
)

// CacheCgroupIDToPod populates the cgroupCache map with mappings from cgroup IDs to a pod.
// It handles both regular pods by iterating through all containers (regular, init, and ephemeral), finds their
// cgroup IDs, and stores the cgroup ID to pod mapping.
//
// Example cgroup paths to parse for container ID and pod UID:
// kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<UID>.slice/cri-containerd-<containerID>.scope (AKS with Cilium)
// kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod<UID>.slice/cri-containerd-<containerID>.scope
// kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod<UID>.slice/cri-containerd-<containerID>.scope
// kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod<UID>.slice/docker-<containerID>.scope (KinD with docker)
func CacheCgroupIDToPod(pod *v1.Pod, cgroupToPodCache map[uint64]*kubernetes.PodMeta, podToCgroupCache map[string][]uint64) error {
	if pod == nil {
		return fmt.Errorf("pod is nil")
	}

	if cgroupToPodCache == nil {
		return fmt.Errorf("cgroup cache is nil")
	}

	if podToCgroupCache == nil {
		return fmt.Errorf("cgroupPodCache is nil")
	}

	podUID := string(pod.UID)

	var allContainers []v1.ContainerStatus
	allContainers = append(allContainers, pod.Status.ContainerStatuses...)
	allContainers = append(allContainers, pod.Status.InitContainerStatuses...)
	allContainers = append(allContainers, pod.Status.EphemeralContainerStatuses...)

	var allErr error
	for _, container := range allContainers {
		if container.ContainerID == "" {
			continue
		}

		containerID := extractContainerId(container)

		cgroupID, err := findContainerCgroupID(containerID, podUID)
		if err != nil {
			allErr = errors.Join(allErr, fmt.Errorf("error finding cgroup ID for container %s in pod %s; %w", containerID, pod.Name, err))
			continue
		}

		cgroupToPodCache[cgroupID] = &kubernetes.PodMeta{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			UID:       pod.UID,
		}
		podToCgroupCache[podUID] = append(podToCgroupCache[podUID], cgroupID)
	}

	return allErr
}

// extractContainerId extracts the container ID from the full container ID string (remove runtime prefix)
func extractContainerId(container v1.ContainerStatus) string {
	containerID := container.ContainerID
	if parts := strings.Split(containerID, "://"); len(parts) == 2 {
		containerID = parts[1]
	}
	return containerID
}

// findContainerCgroupID finds the cgroup ID for a container by searching the cgroup filesystem.
func findContainerCgroupID(containerID string, podUID string) (uint64, error) {
	cgroupRoot := "/sys/fs/cgroup"

	var lastErr error

	// Search in kubepods.slice first
	if cgroupID, err := searchCgroupForContainer(filepath.Join(cgroupRoot, "kubepods.slice"), containerID, podUID); err == nil {
		return cgroupID, nil
	} else {
		lastErr = fmt.Errorf("kubepods.slice: %w", err)
	}

	// Try kubelet.slice
	if cgroupID, err := searchCgroupForContainer(filepath.Join(cgroupRoot, "kubelet.slice"), containerID, podUID); err == nil {
		return cgroupID, nil
	} else {
		lastErr = errors.Join(lastErr, fmt.Errorf("kubelet.slice: %w", err))
	}

	// Try system.slice for KinD with docker
	if cgroupID, err := searchCgroupForContainer(filepath.Join(cgroupRoot, "system.slice"), containerID, podUID); err == nil {
		return cgroupID, nil
	} else {
		lastErr = errors.Join(lastErr, fmt.Errorf("system.slice: %w", err))
	}

	return 0, fmt.Errorf("cgroup not found for container %s: %w", containerID, lastErr)
}

// searchCgroupForContainer searches the cgroup filesystem starting from basePath for a container,
// returning its cgroup ID (inode) if found.
func searchCgroupForContainer(basePath string, containerID string, podUID string) (uint64, error) {
	if _, err := os.Stat(basePath); err != nil {
		return 0, err
	}

	// Normalize pod UID to use underscores (cgroup format) instead of hyphens (k8s format)
	normalizedPodUID := strings.ReplaceAll(podUID, "-", "_")

	// Try common QoS class paths first (fast path)
	for _, qosClass := range []string{"burstable", "besteffort", "guaranteed"} {
		for _, containerRuntime := range []string{"cri-containerd", "docker", "cri-o"} {
			// Common path patterns
			paths := []string{
				filepath.Join(basePath, fmt.Sprintf("kubepods-%s.slice", qosClass), fmt.Sprintf("kubepods-%s-pod%s.slice", qosClass, normalizedPodUID), fmt.Sprintf("%s-%s.scope", containerRuntime, containerID)),
				filepath.Join(basePath, fmt.Sprintf("kubelet-kubepods-%s.slice", qosClass), fmt.Sprintf("kubelet-kubepods-%s-pod%s.slice", qosClass, normalizedPodUID), fmt.Sprintf("cri-containerd-%s.scope", containerID)),
				filepath.Join(basePath, fmt.Sprintf("kubelet-kubepods-%s.slice", qosClass), fmt.Sprintf("kubelet-kubepods-%s-pod%s.slice", qosClass, normalizedPodUID), fmt.Sprintf("docker-%s.scope", containerID)),
			}

			for _, path := range paths {
				if cgroupID, err := getCgroupIDFromPath(path); err == nil {
					return cgroupID, nil
				}
			}
		}
	}

	// Fall back to recursive search for edge cases
	return searchCgroupForContainerRecursive(basePath, containerID, podUID)
}

// getCgroupIDFromPath returns the cgroup ID (inode) for a given path if it exists
func getCgroupIDFromPath(path string) (uint64, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return 0, err
	}

	if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
		return sys.Ino, nil
	}
	return 0, fmt.Errorf("failed to get stat info")
}

// searchCgroupForContainerRecursive recursively searches for a container in the cgroup hierarchy.
func searchCgroupForContainerRecursive(basePath string, containerID string, podUID string) (uint64, error) {
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return 0, err
	}

	// Normalize pod UID to use underscores (cgroup format) instead of hyphens (k8s format)
	normalizedPodUID := strings.ReplaceAll(podUID, "-", "_")

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		fullPath := filepath.Join(basePath, entry.Name())
		name := entry.Name()

		// Check if this directory name contains the container ID
		if strings.Contains(name, containerID) {
			// For kubelet.slice, verify it's in the right pod. For system.slice (KinD docker),
			// the pod UID may not be in the path, so we accept the match if container ID is found.
			if strings.Contains(fullPath, normalizedPodUID) || strings.Contains(basePath, "system.slice") {
				stat, err := os.Stat(fullPath)
				if err != nil {
					continue
				}

				if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
					return sys.Ino, nil
				}
			}
		}

		// Recurse into subdirectories
		if result, err := searchCgroupForContainerRecursive(fullPath, containerID, podUID); err == nil {
			return result, nil
		}
	}

	return 0, fmt.Errorf("container not found")
}
