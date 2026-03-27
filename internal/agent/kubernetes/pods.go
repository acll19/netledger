package kubernetes

import (
	"log"

	"github.com/acll19/netledger/internal/kubernetes"
	"k8s.io/apimachinery/pkg/types"
)

type PodMeta struct {
	Name      string
	Namespace string
	UID       types.UID
}

func WatchPods(onPodAdd, onPodDelete func(obj any), onPodUpdate func(oldObj, newObj any)) {
	clientset, err := kubernetes.GetKubernetesClient()
	if err != nil {
		log.Fatalf("Error creating Kubernetes client: %v", err)
	}

	kubernetes.WatchPods(clientset, onPodAdd, onPodDelete, onPodUpdate)
}
