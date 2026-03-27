package kubernetes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

// GetKubernetesClient returns a Kubernetes clientset
func GetKubernetesClient() (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error

	config, err = rest.InClusterConfig()
	if err == nil {
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			return nil, fmt.Errorf("error creating Kubernetes client (in-cluster): %w", err)
		}
		return clientset, nil
	}

	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, errors.New("cannot determine home directory for kubeconfig fallback")
		}
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("error creating Kubernetes config from kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating Kubernetes client: %w", err)
	}

	return clientset, nil
}

func WatchPods(stopCh <-chan struct{}, client kubernetes.Interface, onPodAdd, onPodDelete func(obj any), onPodUpdate func(oldObj, newObj any)) {
	watchList := cache.NewListWatchFromClient(
		client.CoreV1().RESTClient(),
		"pods",
		metav1.NamespaceAll,
		fields.Everything(),
	)

	_, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: watchList,
		ObjectType:    &v1.Pod{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    onPodAdd,
			UpdateFunc: onPodUpdate,
			DeleteFunc: onPodDelete,
		},
	})

	controller.Run(stopCh)
}
