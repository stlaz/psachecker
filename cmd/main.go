package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/stlaz/psachecker/pkg/checker"
)

func main() {
	flags := pflag.NewFlagSet("psachecker", pflag.ExitOnError)
	pflag.CommandLine = flags

	validationCmd := newCmd()
	if err := validationCmd.Execute(); err != nil {
		os.Exit(1)
	}

}

func newCmd() *cobra.Command {
	o := checker.NewPSACheckerOptions()

	cmd := &cobra.Command{
		Use:          "psachecker resourceType resourceName [flags]",
		Short:        "get the least privileged PodSecurity level for your workload/namespace to keep current workloads running successfully",
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			o.Complete(args)
			// o.Validate

			resp, err := o.Run(context.Background())
			if err != nil {
				return err
			}

			fmt.Fprintf(c.OutOrStdout(), "allowed: %v; audit: %v, warn: %v", resp.Allowed, resp.AuditAnnotations, resp.Warnings)
			return nil
		},
	}

	o.AddFlags(cmd)
	// TODO: add filename options - see https://github.com/kubernetes/kubernetes/blob/9a75e7b0fd1b567f774a3373be640e19b33e7ef1/staging/src/k8s.io/kubectl/pkg/cmd/util/helpers.go#L405

	return cmd
}
