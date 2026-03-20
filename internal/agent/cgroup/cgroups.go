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
// Note: For hostNetwork pods, this function has a limitation when multiple hostNetwork pods exist on the same node.
// Since hostNetwork pods share the host's network namespace and have no container boundary in the cgroup path,
// matching relies on pattern matching (pod UID in path or KinD indicators). The function will return the first
// matching pod and cannot definitively distinguish between multiple hostNetwork pods with similar cgroup path patterns.
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

// TODO: also keep a map of pod UID to slice of cgroup IDs for handling pod deletions

// CacheCgroupIDToPod populates the cgroupCache map with mappings from cgroup IDs to a pod.
// It handles both regular pods and hostNetwork pods:
//   - For regular pods: iterates through all containers (regular, init, and ephemeral), finds their
//     cgroup IDs, and stores the cgroup ID to pod mapping.
//   - For hostNetwork pods: searches for the pod UID in cgroup paths since hostNetwork pods share
//     the host's network namespace and have no container boundary in the cgroup path.
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

	// Handle hostNetwork pods separately
	if pod.Spec.HostNetwork {
		return cacheHostNetworkPodCgroupID(podCgroupCache, pod, podUID)
	}

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

// cacheHostNetworkPodCgroupID finds and caches cgroup IDs for a hostNetwork pod by searching for the pod UID.
// Since hostNetwork pods share the host's network namespace, they have no container boundary in the cgroup path,
// so we match based on pod UID or KinD indicators instead.
func cacheHostNetworkPodCgroupID(cgroupCache map[uint64]*v1.Pod, pod *v1.Pod, podUID string) error {
	cgroupRoot := "/sys/fs/cgroup"

	// Search in kubelet.slice first (most common)
	if cgroupIDs, err := findHostNetworkPodCgroupIDs(filepath.Join(cgroupRoot, "kubelet.slice"), podUID); err == nil {
		for _, cgroupID := range cgroupIDs {
			cgroupCache[cgroupID] = pod
		}
		if len(cgroupIDs) > 0 {
			return nil
		}
	}

	// Try system.slice for KinD with docker
	if cgroupIDs, err := findHostNetworkPodCgroupIDs(filepath.Join(cgroupRoot, "system.slice"), podUID); err == nil {
		for _, cgroupID := range cgroupIDs {
			cgroupCache[cgroupID] = pod
		}
		if len(cgroupIDs) > 0 {
			return nil
		}
	}

	return fmt.Errorf("no cgroup IDs found for hostNetwork pod %s", podUID)
}

// findHostNetworkPodCgroupIDs searches for all cgroup IDs belonging to a hostNetwork pod.
// It matches cgroup paths containing the pod UID or KinD docker indicators.
func findHostNetworkPodCgroupIDs(basePath string, podUID string) ([]uint64, error) {
	if _, err := os.Stat(basePath); err != nil {
		return nil, err
	}

	var cgroupIDs []uint64
	findHostNetworkPodCgroupIDsRecursively(basePath, podUID, &cgroupIDs)
	return cgroupIDs, nil
}

// findHostNetworkPodCgroupIDsRecursive recursively searches for cgroup IDs belonging to a hostNetwork pod.
func findHostNetworkPodCgroupIDsRecursively(basePath string, podUID string, cgroupIDs *[]uint64) {
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		fullPath := filepath.Join(basePath, entry.Name())

		// Check if this matches a hostNetwork pod by pod UID
		if strings.Contains(fullPath, podUID) {
			stat, err := os.Stat(fullPath)
			if err != nil {
				continue
			}

			if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
				*cgroupIDs = append(*cgroupIDs, sys.Ino)
			}
		}

		// For KinD with docker, check if the docker container is in the path and has kubelet cgroups
		if strings.Contains(entry.Name(), "docker-") && strings.Contains(fullPath, "kubelet.slice") {
			stat, err := os.Stat(fullPath)
			if err != nil {
				continue
			}

			if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
				*cgroupIDs = append(*cgroupIDs, sys.Ino)
			}
		}

		// Recurse into subdirectories
		findHostNetworkPodCgroupIDsRecursively(fullPath, podUID, cgroupIDs)
	}
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
