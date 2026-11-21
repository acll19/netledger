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

type WatchEventAddDeleteHandler func(obj any)
type WatchEventUpdateHandler func(oldObj, newObj any)
type StopChannel <-chan struct{}

type WatchOptions struct {
	FilterNodeName string
	Transformer    cache.TransformFunc
}

func WatchPods(
	stopCh StopChannel,
	client kubernetes.Interface, onPodAdd,
	onPodDelete WatchEventAddDeleteHandler,
	onPodUpdate WatchEventUpdateHandler, opts WatchOptions,
) {
	fieldsSelector := fields.Everything()
	if opts.FilterNodeName != "" {
		fieldsSelector = fields.OneTermEqualSelector("spec.nodeName", opts.FilterNodeName)
	}
	watchList := cache.NewListWatchFromClient(
		client.CoreV1().RESTClient(),
		"pods",
		metav1.NamespaceAll,
		fieldsSelector,
	)

	_, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: watchList,
		ObjectType:    &v1.Pod{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    onPodAdd,
			UpdateFunc: onPodUpdate,
			DeleteFunc: onPodDelete,
		},
		Transform: opts.Transformer,
	})

	controller.Run(stopCh)
}
