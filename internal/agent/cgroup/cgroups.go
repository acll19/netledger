package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	v1 "k8s.io/api/core/v1"
)

// TODO: also keep a map of pod UID to slice of cgroup IDs for handling pod deletions

// CacheCgroupIDToPod populates the cgroupCache map with mappings from cgroup IDs to a pod.
// It handles both regular pods by iterating through all containers (regular, init, and ephemeral), finds their
// cgroup IDs, and stores the cgroup ID to pod mapping.
//
// Example cgroup paths to parse for container ID and pod UID:
// kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod<UID>.slice/cri-containerd-<containerID>.scope
// kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod<UID>.slice/cri-containerd-<containerID>.scope
// kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod<UID>.slice/docker-<containerID>.scope (KinD with docker)
func CacheCgroupIDToPod(podCgroupCache map[uint64]*v1.Pod, pod *v1.Pod) error {
	if pod == nil {
		return fmt.Errorf("pod is nil")
	}
	if podCgroupCache == nil {
		return fmt.Errorf("cgroup cache is nil")
	}

	podUID := string(pod.UID)

	// Collect all containers from all sources
	var allContainers []v1.ContainerStatus
	allContainers = append(allContainers, pod.Status.ContainerStatuses...)
	allContainers = append(allContainers, pod.Status.InitContainerStatuses...)
	allContainers = append(allContainers, pod.Status.EphemeralContainerStatuses...)

	var allErr error
	for _, container := range allContainers {
		if container.ContainerID == "" {
			continue
		}

		// Extract the container ID from the full container ID string (remove runtime prefix)
		containerID := container.ContainerID
		if parts := strings.Split(containerID, "://"); len(parts) == 2 {
			containerID = parts[1]
		}

		// Try to find this container's cgroup ID
		cgroupID, err := findContainerCgroupID(containerID, podUID)
		if err != nil {
			allErr = errors.Join(allErr, fmt.Errorf("error finding cgroup ID for container %s in pod %s; %w", containerID, pod.Name, err))
			continue
		}

		podCgroupCache[cgroupID] = pod
	}

	return allErr
}

// findContainerCgroupID finds the cgroup ID for a container by searching the cgroup filesystem.
func findContainerCgroupID(containerID string, podUID string) (uint64, error) {
	cgroupRoot := "/sys/fs/cgroup"

	var lastErr error

	// Search in kubelet.slice first (most common)
	if cgroupID, err := searchCgroupForContainer(filepath.Join(cgroupRoot, "kubelet.slice"), containerID, podUID); err == nil {
		return cgroupID, nil
	} else {
		lastErr = fmt.Errorf("kubelet.slice: %w", err)
	}

	// Try system.slice for KinD with docker
	if cgroupID, err := searchCgroupForContainer(filepath.Join(cgroupRoot, "system.slice"), containerID, podUID); err == nil {
		return cgroupID, nil
	} else {
		lastErr = fmt.Errorf("system.slice: %w", err)
	}

	return 0, fmt.Errorf("cgroup not found for container %s: %w", containerID, lastErr)
}

// searchCgroupForContainer searches the cgroup filesystem starting from basePath for a container,
// returning its cgroup ID (inode) if found.
func searchCgroupForContainer(basePath string, containerID string, podUID string) (uint64, error) {
	// Check if the base path exists
	if _, err := os.Stat(basePath); err != nil {
		return 0, err
	}

	return searchCgroupForContainerRecursive(basePath, containerID, podUID)
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
