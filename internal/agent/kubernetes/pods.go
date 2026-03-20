package kubernetes

import (
	"log"

	"github.com/acll19/netledger/internal/kubernetes"
)

func WatchPods(onPodAdd, onPodDelete func(obj any), onPodUpdate func(oldObj, newObj any)) {
	clientset, err := kubernetes.GetKubernetesClient()
	if err != nil {
		log.Fatalf("Error creating Kubernetes client: %v", err)
	}

	kubernetes.WatchPods(clientset, onPodAdd, onPodDelete, onPodUpdate)
}
