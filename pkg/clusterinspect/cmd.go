package clusterinspect

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewClusterInspectCommand(clientConfigOptions *genericclioptions.ConfigFlags) *cobra.Command {
	o := newClusterInspectOptions()

	cmd := &cobra.Command{
		Use:          "inspect-cluster [flags]",
		Short:        "get the least privileged PodSecurity level for your workload/namespace to keep current workloads running successfully",
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			o.Complete(c, clientConfigOptions)

			nsAggregatedResults, err := o.Run(context.Background())
			if err != nil {
				return err
			}

			for _, ns := range nsAggregatedResults.Keys() {
				fmt.Fprintf(c.OutOrStdout(), "%s: %s\n", ns, nsAggregatedResults.Get(ns))
			}
			return nil
		},
	}

	return cmd
}
