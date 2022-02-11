package workloadinspect

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stlaz/psachecker/pkg/admission"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/kubernetes"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	psapi "k8s.io/pod-security-admission/api"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(appsv1.AddToScheme(scheme))
	utilruntime.Must(batchv1.AddToScheme(scheme))
}

type WorkloadInspectOptions struct {
	clientConfigOptions *genericclioptions.ConfigFlags
	filenameOptions     *resource.FilenameOptions

	updatesOnly       bool
	defaultNamespaces bool

	builder    *resource.Builder
	kubeClient kubernetes.Interface

	isLocal bool
}

func newWorkloadInspectOptions() *WorkloadInspectOptions {
	return &WorkloadInspectOptions{
		filenameOptions: &resource.FilenameOptions{},
	}
}

func (o *WorkloadInspectOptions) AddFlags(cmd *cobra.Command) {
	flags := cmd.Flags()

	cmdutil.AddFilenameOptionFlags(cmd, // TODO: this adds a kustomize flag, do we need to special-case handle it?
		o.filenameOptions,
		"identifying the resource to run PodSecurity admission check against",
	)

	flags.BoolVar(&o.defaultNamespaces, "default-namespaces", false, "Default empty namespaces in files to the --namespace value.")
}

func (o *WorkloadInspectOptions) Complete(cmd *cobra.Command, args []string, clientConfigOptions *genericclioptions.ConfigFlags) error {
	o.updatesOnly = cmdutil.GetFlagBool(cmd, "updates-only")
	o.clientConfigOptions = clientConfigOptions

	clientConfig, err := o.clientConfigOptions.ToRawKubeConfigLoader().ClientConfig()
	if err != nil {
		return err
	}

	o.kubeClient, err = kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return err
	}

	o.builder = resource.NewBuilder(o.clientConfigOptions).
		WithScheme(scheme,
			corev1.SchemeGroupVersion,
			appsv1.SchemeGroupVersion,
			batchv1.SchemeGroupVersion,
		)

	// make the builder accept files if provided, otherwise expect resourceType and name
	if files := o.filenameOptions.Filenames; len(files) > 0 {
		o.builder = o.builder.
			Local().
			FilenameParam(false, o.filenameOptions)

		o.isLocal = true
	} else {
		o.builder = o.builder.
			SingleResourceType().
			ResourceTypeOrNameArgs(true, args...)
	}

	if ns := *o.clientConfigOptions.Namespace; len(ns) > 0 {
		o.builder = o.builder.
			NamespaceParam(ns).
			DefaultNamespace()
	}

	return nil
}

func (o *WorkloadInspectOptions) Validate() []error {
	errs := []error{}

	if o.kubeClient == nil {
		errs = append(errs, fmt.Errorf("missing kube client"))
	}

	if o.defaultNamespaces && len(*o.clientConfigOptions.Namespace) == 0 {
		errs = append(errs, fmt.Errorf("cannot specify --default-namespaces without also providing a value for --namespace"))
	}

	return errs
}

func (opts *WorkloadInspectOptions) Run(ctx context.Context) (*admission.OrderedStringToPSALevelMap, error) {
	adm, err := admission.NewParallelAdmission(opts.kubeClient)
	if err != nil {
		return nil, fmt.Errorf("failed to set up admission: %w", err)
	}

	var nsAggregatedResults map[string]psapi.Level

	res := opts.builder.Do()

	infos, err := res.Infos()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve info about the objects: %w", err)
	}

	var defaultNS *string
	if opts.defaultNamespaces {
		defaultNS = opts.clientConfigOptions.Namespace
	}

	results, err := adm.ValidateResources(ctx, opts.isLocal, defaultNS, infos...)
	if err != nil {
		return nil, err
	}
	nsAggregatedResults = admission.MostRestrictivePolicyPerNamespace(results)
	if !opts.isLocal && opts.updatesOnly {
		// TODO: list the NSes we've got in the map at the same time instead of going 1-by-1?
		for ns, level := range nsAggregatedResults {
			liveNS, err := opts.kubeClient.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			// FIXME: need to take the global config into account
			if string(level) == liveNS.Labels[psapi.EnforceLevelLabel] {
				delete(nsAggregatedResults, ns)
			}
		}
	}

	return admission.NewOrderedStringToPSALevelMap(nsAggregatedResults), nil
}
