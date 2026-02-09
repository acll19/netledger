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

type ServiceInfo struct {
	Namespace   string
	Name        string
	ClusterIP   string
	Backends    []string
	ExternalIPs []string
	NodePorts   []int32
}

type ServiceKey = string

func NewServiceInfp(svc *v1.Service) (ServiceKey, ServiceInfo) {
	svcInfo := ServiceInfo{
		Name:        svc.Name,
		Namespace:   svc.Namespace,
		ClusterIP:   svc.Spec.ClusterIP,
		ExternalIPs: svc.Spec.ExternalIPs,
	}

	key := svc.Spec.ClusterIP
	if svc.Spec.Type == v1.ServiceTypeNodePort {
		for _, p := range svc.Spec.Ports {
			svcInfo.NodePorts = append(svcInfo.NodePorts, p.NodePort)
		}
	}

	if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
		key = svc.Status.LoadBalancer.Ingress[0].IP
		if key == "" {
			key = svcInfo.ExternalIPs[0]
		}
	}

	return key, svcInfo
}

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

func WatchEndpointSlices(client *kubernetes.Clientset, onAdd, onDelete func(obj any), onUpdate func(oldObj, newObj any)) {
	watchList := cache.NewListWatchFromClient(
		client.DiscoveryV1().RESTClient(),
		"endpointslices",
		metav1.NamespaceAll,
		fields.Everything(),
	)

	_, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: watchList,
		ObjectType:    &discovery.EndpointSlice{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    onAdd,
			DeleteFunc: onDelete,
			UpdateFunc: onUpdate,
		},
	})
	controller.Run(make(chan struct{}))
}

func SetupServicesInformer(ctx context.Context, client *kubernetes.Clientset) (cache.SharedIndexInformer, error) {
	factory := informers.NewSharedInformerFactoryWithOptions(client, 0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {}))
	informer := factory.Core().V1().Services().Informer()
	go informer.Run(ctx.Done())

	// Wait for the initial LIST to populate the cache
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return nil, fmt.Errorf("timed out waiting for caches to sync")
	}

	return informer, nil
}

func SetupEndpointSlicesInformer(ctx context.Context, client *kubernetes.Clientset) (cache.SharedIndexInformer, error) {
	factory := informers.NewSharedInformerFactoryWithOptions(client, 0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {}))
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
