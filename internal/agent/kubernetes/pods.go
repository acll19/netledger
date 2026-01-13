package kubernetes

import (
	"context"
	"fmt"
	"log"

	"github.com/acll19/netledger/internal/kubernetes"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

func SetupPodInformer(ctx context.Context, node string) (cache.SharedIndexInformer, error) {
	clientset, err := kubernetes.GetKubernetesClient()
	if err != nil {
		return nil, fmt.Errorf("Error creating Kubernetes client %w", err)
	}

	log.Println("Watching pods for node: ", node)
	factory := informers.NewSharedInformerFactoryWithOptions(clientset, 0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = "spec.nodeName=" + node
		}))
	informer := factory.Core().V1().Pods().Informer()
	go informer.Run(ctx.Done())

	// Wait for the initial LIST to populate the cache
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return nil, fmt.Errorf("timed out waiting for caches to sync")
	}

	return informer, nil
}

func GetPods(informer cache.SharedIndexInformer) []*v1.Pod {
	objs := informer.GetStore().List()
	res := make([]*v1.Pod, 0, len(objs))

	for _, obj := range objs {
		res = append(res, obj.(*v1.Pod))
	}

	return res
}
