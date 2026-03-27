package kubernetes

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

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
