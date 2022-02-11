package workloadinspect

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewWorkloadInspectCommand(clientConfigOptions *genericclioptions.ConfigFlags) *cobra.Command {
	o := newWorkloadInspectOptions()

	cmd := &cobra.Command{
		Use:          "inspect-workloads [flags]",
		Short:        "get the least privileged PodSecurity level for your workload to keep current workloads running successfully",
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			o.Complete(c, args, clientConfigOptions)
			errs := o.Validate()
			if len(errs) > 0 {
				return fmt.Errorf("there were errors while setting up the command: %v", errs)
			}

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

	o.AddFlags(cmd)
	return cmd
}
