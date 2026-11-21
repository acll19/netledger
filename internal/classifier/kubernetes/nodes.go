package kubernetes

import (
	ck8s "github.com/acll19/netledger/internal/kubernetes"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	NodeLabelZone   = "topology.kubernetes.io/zone"
	NodeLabelRegion = "topology.kubernetes.io/region"
)

func WatchNodes(
	stopCh ck8s.StopChannel,
	client kubernetes.Interface,
	onNodeAdd, onNodeDelete ck8s.WatchEventAddDeleteHandler,
	onNodeUpdate ck8s.WatchEventUpdateHandler,
) {
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
		Transform: func(obj any) (any, error) {
			node, ok := obj.(*v1.Node)
			if !ok {
				return obj, nil
			}
			return &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:      node.Name,
					Namespace: node.Namespace,
					UID:       node.UID,
					Labels: map[string]string{
						NodeLabelZone:   node.Labels[NodeLabelZone],
						NodeLabelRegion: node.Labels[NodeLabelRegion],
					},
				},
				Status: v1.NodeStatus{
					Addresses:  node.Status.Addresses,
					Conditions: node.Status.Conditions,
				},
			}, nil
		},
	})
	controller.Run(stopCh)
}
