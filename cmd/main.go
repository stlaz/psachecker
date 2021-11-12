package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/kubernetes"
	psadmission "k8s.io/pod-security-admission/admission"

	"github.com/stlaz/psachecker/pkg/admission"
)

var (
	resourceTypes = []string{
		"pods",
		"replicationcontrollers",
		"podtemplates",
		"replicasets",
		"deployments",
		"statefulsets",
		"daemonsets",
		"jobs",
		"cronjobs",
	}
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(appsv1.AddToScheme(scheme))
	utilruntime.Must(batchv1.AddToScheme(scheme))
}

func main() {
	flags := pflag.NewFlagSet("psachecker", pflag.ExitOnError)
	pflag.CommandLine = flags

	validationCmd := newCmd()
	if err := validationCmd.Execute(); err != nil {
		os.Exit(1)
	}

}

func newCmd() *cobra.Command {
	// TODO: have an options object that encapsulates all this?
	clientConfigOpts := genericclioptions.NewConfigFlags(true)
	// filenameOpts := resource.FilenameOptions{}

	cmd := &cobra.Command{
		Use:          "psachecker resourceType resourceName [flags]",
		Short:        "get the least privileged PodSecurity level for your workload/namespace to keep current workloads running successfully",
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			// o.Complete
			// o.Validate
			config, err := clientConfigOpts.ToRawKubeConfigLoader().ClientConfig()
			if err != nil {
				return err
			}

			kubeClient, err := kubernetes.NewForConfig(config)
			if err != nil {
				return err
			}
			// o.Run
			adm, err := admission.SetupAdmission(kubeClient) // TODO: allow mocking e.g. namespaces without a live client
			if err != nil {
				return err
			}

			resourceBuilder := resource.NewBuilder(clientConfigOpts).
				WithScheme(scheme, corev1.SchemeGroupVersion, appsv1.SchemeGroupVersion, batchv1.SchemeGroupVersion).
				NamespaceParam(*clientConfigOpts.Namespace).
				ResourceTypeOrNameArgs(true, args...)
			// resourceBuilder.FilenameParam(false, &filenameOpts)
			resource := resourceBuilder.Do()

			obj, err := resource.Object()
			if err != nil {
				return fmt.Errorf("failed to retrieve resource from the arguments: %v", err)
			}

			mapping, err := resource.ResourceMapping()
			if err != nil {
				return fmt.Errorf("failed to retrieve resource mapping: %v", err)
			}

			ctx := context.Background()
			resp := adm.Validate(ctx, &psadmission.AttributesRecord{
				Namespace: obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(), // TODO: get the meta obj earlier, reuse
				Name:      obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName(),
				Resource:  mapping.Resource,
				Operation: admissionv1.Create,
				Object:    obj,
				Username:  "", // TODO: do we need this? What's it for anyway?
			})

			fmt.Fprintf(c.OutOrStdout(), "allowed: %v; audit: %v, warn: %v", resp.Allowed, resp.AuditAnnotations, resp.Warnings)
			return err
		},
	}

	clientConfigOpts.AddFlags(cmd.Flags())
	// TODO: add filename options - see https://github.com/kubernetes/kubernetes/blob/9a75e7b0fd1b567f774a3373be640e19b33e7ef1/staging/src/k8s.io/kubectl/pkg/cmd/util/helpers.go#L405

	return cmd
}
