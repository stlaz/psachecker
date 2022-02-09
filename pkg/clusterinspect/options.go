package clusterinspect

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	psapi "k8s.io/pod-security-admission/api"

	"github.com/stlaz/psachecker/pkg/checker"
)

type ClusterInspectOptions struct {
	clientConfigOptions *genericclioptions.ConfigFlags

	updatesOnly bool

	kubeClient kubernetes.Interface
}

func newClusterInspectOptions() *ClusterInspectOptions {
	return &ClusterInspectOptions{}
}

func (o *ClusterInspectOptions) Complete(cmd *cobra.Command, clientConfigOptions *genericclioptions.ConfigFlags) error {
	o.updatesOnly = cmdutil.GetFlagBool(cmd, "updates-only")
	o.clientConfigOptions = clientConfigOptions

	clientConfig, err := o.clientConfigOptions.ToRawKubeConfigLoader().ClientConfig()
	if err != nil {
		return fmt.Errorf("failed to read kube client configuration")
	}

	o.kubeClient, err = kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return fmt.Errorf("failed to create kube client: %w", err)
	}

	return nil
}

func (o *ClusterInspectOptions) Run(ctx context.Context) (*checker.OrderedStringToPSALevelMap, error) {
	adm, err := checker.NewParallelAdmission(o.kubeClient)
	if err != nil {
		return nil, fmt.Errorf("failed to set up admission: %w", err)
	}

	namespacesList, err := o.kubeClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	nsAggregatedResults, err := adm.ValidateNamespaces(ctx, namespacesList.Items...)
	if err != nil {
		return nil, err
	}
	if o.updatesOnly {
		for _, origNS := range namespacesList.Items {
			suggestedLevel := nsAggregatedResults[origNS.Name]
			// FIXME: we need to take the global config into account during the validation otherwise
			//        this is going to include NSes that don't need updating
			if string(suggestedLevel) == origNS.Labels[psapi.EnforceLevelLabel] {
				delete(nsAggregatedResults, origNS.Name)
			}
		}
	}

	return checker.NewOrderedStringToPSALevelMap(nsAggregatedResults), nil
}
