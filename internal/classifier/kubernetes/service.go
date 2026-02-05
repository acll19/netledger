package kubernetes

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func WatchServices(client *kubernetes.Clientset, onAdd, onDelete func(obj any), onUpdate func(oldObj, newObj any)) {
	watchList := cache.NewListWatchFromClient(
		client.CoreV1().RESTClient(),
		"services",
		metav1.NamespaceAll,
		fields.Everything(),
	)

	_, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: watchList,
		ObjectType:    &v1.Service{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    onAdd,
			DeleteFunc: onDelete,
			UpdateFunc: onUpdate,
		},
	})
	controller.Run(make(chan struct{}))
}

func SetupEndpointSlicesInformer(ctx context.Context, client *kubernetes.Clientset) (cache.SharedIndexInformer, error) {
	factory := informers.NewSharedInformerFactoryWithOptions(client, 0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.LabelSelector = "kubernetes.io/service-name"
		}))
	informer := factory.Discovery().V1().EndpointSlices().Informer()
	go informer.Run(ctx.Done())

	// Wait for the initial LIST to populate the cache
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return nil, fmt.Errorf("timed out waiting for caches to sync")
	}

	return informer, nil
}

func GetEndpointSlices(informer cache.SharedIndexInformer) []*discovery.EndpointSlice {
	objs := informer.GetStore().List()
	res := make([]*discovery.EndpointSlice, 0, len(objs))

	for _, obj := range objs {
		res = append(res, obj.(*discovery.EndpointSlice))
	}

	return res
}
