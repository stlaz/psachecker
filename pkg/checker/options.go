package checker

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

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
	"k8s.io/client-go/rest"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	psadmission "k8s.io/pod-security-admission/admission"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(appsv1.AddToScheme(scheme))
	utilruntime.Must(batchv1.AddToScheme(scheme))
}

type PSACheckerOptions struct {
	clientConfigOptions *genericclioptions.ConfigFlags
	filenameOptions     *resource.FilenameOptions

	builder    *resource.Builder
	nsGetter   psadmission.NamespaceGetter
	kubeClient kubernetes.Interface
}

func NewPSACheckerOptions() *PSACheckerOptions {
	return &PSACheckerOptions{
		clientConfigOptions: genericclioptions.NewConfigFlags(true),
		filenameOptions:     &resource.FilenameOptions{},
	}
}

func (opts *PSACheckerOptions) AddFlags(cmd *cobra.Command) {
	opts.clientConfigOptions.AddFlags(cmd.Flags())
	cmdutil.AddFilenameOptionFlags(cmd, // TODO: this adds a kustomize flag, do we need to special-case handle it?
		opts.filenameOptions,
		"identifying the resource to run PodSecurity admission check against",
	)
}

func (opts *PSACheckerOptions) ClientConfig() (*rest.Config, error) {
	return opts.clientConfigOptions.ToRawKubeConfigLoader().ClientConfig()
}

func (opts *PSACheckerOptions) ResourceBuilder() *resource.Builder {
	return resource.NewBuilder(opts.clientConfigOptions)
}

func (opts *PSACheckerOptions) Complete(args []string) error {
	clientConfig, err := opts.clientConfigOptions.ToRawKubeConfigLoader().ClientConfig()
	if err != nil {
		return err
	}

	opts.kubeClient, err = kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return err
	}

	opts.builder = resource.NewBuilder(opts.clientConfigOptions).
		WithScheme(scheme, corev1.SchemeGroupVersion, appsv1.SchemeGroupVersion, batchv1.SchemeGroupVersion)

	// make the builder accept files if provided, otherwise expect resourceType and name
	if files := opts.filenameOptions.Filenames; len(files) > 0 {
		opts.builder = opts.builder.FilenameParam(false, opts.filenameOptions)
		opts.nsGetter = KnowAllNamespaceGetter
	} else {
		opts.builder = opts.builder.SingleResourceType().
			ResourceTypeOrNameArgs(true, args...)
	}

	if ns := *opts.clientConfigOptions.Namespace; len(ns) > 0 {
		opts.builder = opts.builder.DefaultNamespace().
			NamespaceParam(ns)
	}

	return nil
}

func (opts *PSACheckerOptions) Run(ctx context.Context) (*admissionv1.AdmissionResponse, error) {
	res := opts.builder.Do()

	infos, err := res.Infos()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve info about the objects: %w", err)
	}

	if numInfos := len(infos); numInfos != 1 { // FIXME: only for simplicity now, allow passing multiple objects in a single NS later
		return nil, fmt.Errorf("got unexpected number of objects: %d", numInfos)
	}

	adm, err := SetupAdmission(opts.kubeClient)
	if err != nil {
		return nil, fmt.Errorf("failed to set up admission: %w", err)
	}

	admResp := adm.Validate(ctx, &psadmission.AttributesRecord{
		Namespace: infos[0].Object.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(), // TODO: get the meta obj earlier, reuse
		Name:      infos[0].Object.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName(),
		Resource:  infos[0].Mapping.Resource,
		Operation: admissionv1.Create,
		Object:    infos[0].Object,
		Username:  "", // TODO: do we need this? What's it for anyway?
	})

	return admResp, nil
}
