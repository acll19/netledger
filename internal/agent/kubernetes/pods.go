package kubernetes

import (
	"log"

	"github.com/acll19/netledger/internal/kubernetes"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type PodMeta struct {
	Name      string
	Namespace string
	UID       types.UID
}

func WatchPods(stopCh kubernetes.StopChannel,
	nodeName string,
	onPodAdd,
	onPodDelete kubernetes.WatchEventAddDeleteHandler,
	onPodUpdate kubernetes.WatchEventUpdateHandler,
) {
	clientset, err := kubernetes.GetKubernetesClient()
	if err != nil {
		log.Fatalf("Error creating Kubernetes client: %v", err)
	}

	opts := kubernetes.WatchOptions{
		FilterNodeName: nodeName,
		Transformer: func(obj any) (any, error) {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				return obj, nil
			}
			return &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      pod.Name,
					Namespace: pod.Namespace,
					UID:       pod.UID,
				},
				Status: v1.PodStatus{
					PodIP:                      pod.Status.PodIP,
					PodIPs:                     pod.Status.PodIPs,
					Phase:                      pod.Status.Phase,
					ContainerStatuses:          trimContainerStatuses(pod.Status.ContainerStatuses),
					InitContainerStatuses:      trimContainerStatuses(pod.Status.InitContainerStatuses),
					EphemeralContainerStatuses: trimContainerStatuses(pod.Status.EphemeralContainerStatuses),
				},
			}, nil
		},
	}
	kubernetes.WatchPods(stopCh, clientset, onPodAdd, onPodDelete, onPodUpdate, opts)
}

func trimContainerStatuses(statuses []v1.ContainerStatus) []v1.ContainerStatus {
	trimmed := make([]v1.ContainerStatus, len(statuses))
	for i, status := range statuses {
		trimmed[i].ContainerID = status.ContainerID
	}
	return trimmed
}
