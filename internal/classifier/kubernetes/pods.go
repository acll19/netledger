package kubernetes

import (
	ck8s "github.com/acll19/netledger/internal/kubernetes"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func WatchPods(
	stopCh ck8s.StopChannel,
	client kubernetes.Interface,
	onPodAdd, onPodDelete ck8s.WatchEventAddDeleteHandler,
	onPodUpdate ck8s.WatchEventUpdateHandler,
) {
	opts := ck8s.WatchOptions{
		FilterNodeName: "",
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
				Spec: v1.PodSpec{
					NodeName: pod.Spec.NodeName,
				},
				Status: v1.PodStatus{
					PodIP:  pod.Status.PodIP,
					PodIPs: pod.Status.PodIPs,
					HostIP: pod.Status.HostIP,
				},
			}, nil
		},
	}

	ck8s.WatchPods(stopCh, client, onPodAdd, onPodDelete, onPodUpdate, opts)
}
