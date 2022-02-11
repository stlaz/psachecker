package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/component-base/cli"

	"github.com/stlaz/psachecker/pkg/clusterinspect"
	"github.com/stlaz/psachecker/pkg/workloadinspect"
)

func main() {
	flags := pflag.NewFlagSet("psachecker", pflag.ExitOnError)
	pflag.CommandLine = flags

	validationCmd := newCmd()
	os.Exit(cli.Run(validationCmd))

}

func newCmd() *cobra.Command {
	o := newPSACheckerOptions()

	cmd := &cobra.Command{
		Use:          "psachecker resourceType resourceName [flags]",
		Short:        "get the least privileged PodSecurity level for your workload/namespace to keep current workloads running successfully",
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			// This is currently only a catch-all for common options
			return nil
		},
	}

	o.AddGlobalFlags(cmd.PersistentFlags())

	cmd.AddCommand(workloadinspect.NewWorkloadInspectCommand(o.ClientConfigOptions))
	cmd.AddCommand(clusterinspect.NewClusterInspectCommand(o.ClientConfigOptions))
	return cmd
}

type PSACheckerOptions struct {
	ClientConfigOptions *genericclioptions.ConfigFlags

	// custom flags
	updatesOnly bool
}

func newPSACheckerOptions() *PSACheckerOptions {
	return &PSACheckerOptions{
		ClientConfigOptions: genericclioptions.NewConfigFlags(true),
	}
}

func (opts *PSACheckerOptions) AddGlobalFlags(globalFlags *pflag.FlagSet) {
	opts.ClientConfigOptions.AddFlags(globalFlags)

	globalFlags.BoolVar(&opts.updatesOnly, "updates-only", false, "Display only namespaces that need to be updated. Does not currently work for local files.")
}
