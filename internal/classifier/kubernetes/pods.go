package kubernetes

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func WatchPods(client kubernetes.Interface, onPodAdd, onPodDelete func(obj any), onPodUpdate func(oldObj, newObj any)) {
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

	controller.Run(make(chan struct{}))
}

func WatchNodes(client kubernetes.Interface, onNodeAdd, onNodeDelete func(obj any), onNodeUpdate func(oldObj, newObj any)) {
	watchList := cache.NewListWatchFromClient(
		client.CoreV1().RESTClient(),
		"nodes",
		metav1.NamespaceAll,
		fields.Everything(),
	)
	_, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: watchList,
		ObjectType:    &v1.Node{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    onNodeAdd,
			UpdateFunc: onNodeUpdate,
			DeleteFunc: onNodeDelete,
		},
	})
	controller.Run(make(chan struct{}))
}
