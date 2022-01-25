package checker

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

	builder *resource.Builder
	// nsGetter for the admission to get the NS rules and possibly check for NS exemption
	nsGetter   psadmission.NamespaceGetter
	kubeClient kubernetes.Interface

	isLocal bool
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
		WithScheme(scheme,
			corev1.SchemeGroupVersion,
			appsv1.SchemeGroupVersion,
			batchv1.SchemeGroupVersion,
		)

	// make the builder accept files if provided, otherwise expect resourceType and name
	if files := opts.filenameOptions.Filenames; len(files) > 0 {
		opts.builder = opts.builder.
			Local().
			FilenameParam(false, opts.filenameOptions)

		opts.nsGetter = KnowAllNamespaceGetter
		opts.isLocal = true
	} else {
		opts.builder = opts.builder.
			SingleResourceType().
			ResourceTypeOrNameArgs(true, args...)
		opts.nsGetter = psadmission.NamespaceGetterFromClient(opts.kubeClient)
	}

	if ns := *opts.clientConfigOptions.Namespace; len(ns) > 0 {
		opts.builder = opts.builder.
			NamespaceParam(ns).
			DefaultNamespace()
	}

	return nil
}

func (opts *PSACheckerOptions) Validate() []error {
	errors := []error{}

	if opts.kubeClient == nil {
		errors = append(errors, fmt.Errorf("missing kube client"))
	}
	if opts.nsGetter == nil {
		errors = append(errors, fmt.Errorf("missing nsGetter"))
	}

	return errors
}

func (opts *PSACheckerOptions) Run(ctx context.Context) (map[string]*ParallelAdmissionResult, error) {
	res := opts.builder.Do()

	infos, err := res.Infos()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve info about the objects: %w", err)
	}

	adm, err := NewParallelAdmission(opts.kubeClient, opts.nsGetter)
	if err != nil {
		return nil, fmt.Errorf("failed to set up admission: %w", err)
	}

	results := map[string]*ParallelAdmissionResult{}
	for _, resInfo := range infos {

		var resource schema.GroupVersionResource
		if resInfo.Mapping != nil {
			resource = resInfo.Mapping.Resource
		} else {
			// TODO: not great, I wonder whether there's a better way to do this for non-server requests
			resource, _ = meta.UnsafeGuessKindToResource(resInfo.Object.GetObjectKind().GroupVersionKind())
		}

		if opts.isLocal && len(resInfo.Object.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace()) == 0 {
			// the resource.Builder DefaultNamespace() won't default namespaces unless Latest() is set but
			// Latest() would attempt to retrieve the data from server (and would panic() on missing RestMapping)
			// so let's just do this
			ns := *opts.clientConfigOptions.Namespace
			if len(ns) == 0 {
				ns = "fairly-random-ns"
			}
			resInfo.Object.(metav1.ObjectMetaAccessor).GetObjectMeta().SetNamespace(ns)
		}

		metaObj := resInfo.Object.(metav1.ObjectMetaAccessor).GetObjectMeta()
		objNS, objName := metaObj.GetNamespace(), metaObj.GetName()
		objKind := resInfo.Object.GetObjectKind()
		key := fmt.Sprintf("gvk: %q - %s/%s", objKind.GroupVersionKind().String(), objNS, objName)

		results[key] = adm.Validate(ctx, &psadmission.AttributesRecord{
			Namespace: objNS,
			Name:      objName,
			Resource:  resource,
			Operation: admissionv1.Create,
			Object:    resInfo.Object,
			Username:  "", // TODO: do we need this? What's it for anyway?
		})
	}

	return results, nil
}
