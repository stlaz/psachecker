package checker

import (
	"context"
	"fmt"
	"sync"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/kubernetes"
	psadmission "k8s.io/pod-security-admission/admission"
	psadmissionapi "k8s.io/pod-security-admission/admission/api"
	psapi "k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"
)

type ParallelAdmission struct {
	privileged *psadmission.Admission
	baseline   *psadmission.Admission
	restricted *psadmission.Admission
}

type ParallelAdmissionResult struct {
	Privileged, Baseline, Restricted *admissionv1.AdmissionResponse
}

type AdmissionResultsKey struct {
	GVK       schema.GroupVersionKind
	Namespace string
	Name      string
}

type AdmissionResultsMap map[AdmissionResultsKey]*ParallelAdmissionResult

func (r *ParallelAdmissionResult) String() string {
	resultString := func(resp *admissionv1.AdmissionResponse) string {
		if resp.Allowed {
			return "allowed"
		}
		return fmt.Sprintf("%s: %s", resp.Result.Status, resp.Result.Message)
	}

	return fmt.Sprintf(
		"privileged: %s\nbaseline: %s\nrestricted: %s\n",
		resultString(r.Privileged),
		resultString(r.Baseline),
		resultString(r.Restricted),
	)
}

const LevelUnknown psapi.Level = psapi.Level("unknown")

func (r *ParallelAdmissionResult) MostRestrictivePolicy() psapi.Level {
	if r.Restricted == nil || r.Baseline == nil || r.Privileged == nil {
		return LevelUnknown
	}

	switch {
	case r.Restricted.Allowed:
		return psapi.LevelRestricted
	case r.Baseline.Allowed:
		return psapi.LevelBaseline
	default:
		return psapi.LevelPrivileged
	}
}

func NewParallelAdmission(kubeClient kubernetes.Interface) (*ParallelAdmission, error) {
	evaluator, err := policy.NewEvaluator(policy.DefaultChecks()) // TODO: allow experimental checks by a flag
	if err != nil {
		return nil, err
	}

	podLister := psadmission.PodListerFromClient(kubeClient) // only used while validating pods in an NS

	// TODO: NamespaceGetter is currently only used to get the policies of the NS
	//       during a given Pod/pod controller evaluation. We do not want the NS
	//       policies to interfere with the admission that we are going to be testing
	//       so we mock NS retrieval all the time w/ empty PSa labels.
	// IMPORTANT: make sure to unit-test that Namespace-object admission validation
	//            is not influenced by nsGetter
	nsGetter := KnowAllNamespaceGetter
	privilegedAdm, err := setupAdmission(nsGetter, podLister, evaluator, psapi.LevelPrivileged)
	if err != nil {
		return nil, err
	}
	baselineAdm, err := setupAdmission(nsGetter, podLister, evaluator, psapi.LevelBaseline)
	if err != nil {
		return nil, err
	}
	restrictedAdm, err := setupAdmission(nsGetter, podLister, evaluator, psapi.LevelRestricted)
	if err != nil {
		return nil, err
	}

	return &ParallelAdmission{
		privileged: privilegedAdm,
		baseline:   baselineAdm,
		restricted: restrictedAdm,
	}, nil
}

func (a *ParallelAdmission) Validate(ctx context.Context, attrs psadmission.Attributes) *ParallelAdmissionResult {
	result := &ParallelAdmissionResult{}
	resultsWG := &sync.WaitGroup{}
	waitForAdmission := func(wg *sync.WaitGroup, admission *psadmission.Admission, result **admissionv1.AdmissionResponse) {
		defer wg.Done()
		*result = admission.Validate(ctx, attrs)
	}

	resultsWG.Add(3)
	go waitForAdmission(resultsWG, a.privileged, &result.Privileged)
	go waitForAdmission(resultsWG, a.baseline, &result.Baseline)
	go waitForAdmission(resultsWG, a.restricted, &result.Restricted)

	resultsWG.Wait()

	return result
}

func (a *ParallelAdmission) ValidateResources(ctx context.Context, localResources bool, defaultNamespace *string, resources ...*resource.Info) (AdmissionResultsMap, error) {
	results := AdmissionResultsMap{}
	for _, resInfo := range resources {

		var resource schema.GroupVersionResource
		if resInfo.Mapping != nil {
			resource = resInfo.Mapping.Resource
		} else {
			// TODO: not great, I wonder whether there's a better way to do this for non-server requests
			resource, _ = meta.UnsafeGuessKindToResource(resInfo.Object.GetObjectKind().GroupVersionKind())
		}

		objMeta := resInfo.Object.(metav1.ObjectMetaAccessor).GetObjectMeta()
		if localResources && len(objMeta.GetNamespace()) == 0 {
			if defaultNamespace == nil {
				return nil, fmt.Errorf("\"%s/%s\" is missing namespace in its definition", resInfo.Object.GetObjectKind().GroupVersionKind().Kind, objMeta.GetName())
			}

			// the resource.Builder DefaultNamespace() won't default namespaces unless Latest() is set but
			// Latest() would attempt to retrieve the data from server (and would panic() on missing RestMapping)
			// so let's just do this
			objMeta.SetNamespace(*defaultNamespace)
		}

		objNS, objName := objMeta.GetNamespace(), objMeta.GetName()
		objKind := resInfo.Object.GetObjectKind()
		key := AdmissionResultsKey{
			GVK:       objKind.GroupVersionKind(),
			Namespace: objNS,
			Name:      objName,
		}

		results[key] = a.Validate(ctx, &psadmission.AttributesRecord{
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

func (a *ParallelAdmission) ValidateNamespaces(ctx context.Context, namespaces ...corev1.Namespace) (map[string]psapi.Level, error) {
	results := make(map[string]psapi.Level)
	for _, ns := range namespaces {
		results[ns.Name] = psapi.LevelPrivileged
		// loop through available levels in order of restrictivness so that more restrictive levels override previous result if they are allowed
		for _, privilegeLevel := range []psapi.Level{psapi.LevelBaseline, psapi.LevelRestricted} {
			newNS := ns.DeepCopy()
			newNS.Labels[psapi.EnforceLevelLabel] = string(privilegeLevel)
			newNS.Labels[psapi.EnforceVersionLabel] = string(psapi.VersionLatest) // FIXME: should this be the earliest version or the current one? Which version should the admission config use?

			// TODO:
			// - perhaps a flag should be added to inspect all workloads instead of namespaces
			//   since the admission only inspects Pods but will ignore pod controllers that
			//   may be stuck
			// - a flag should be added to decide which admission level should run these
			//   validation tests (based on cluster config)
			admissionResult := a.privileged.Validate(ctx, &psadmission.AttributesRecord{
				Name:      ns.Name,
				Resource:  ns.GroupVersionKind().GroupVersion().WithResource("namespaces"),
				Operation: admissionv1.Update,
				OldObject: &ns,
				Object:    newNS,
				Username:  "", // TODO: do we need this? What's it for anyway?
			})

			// the admission does not currently deny on a label change that might
			// prevent the workloads from running, it only requires the PS API labels
			// to be valid if they are specified
			// If there are issues with PSa enforcement, these are passed in the
			// results's `Warnings` attribute`
			if len(admissionResult.Warnings) == 0 {
				results[ns.Name] = privilegeLevel
			}

		}
	}

	return results, nil
}

func setupAdmission(
	nsGetter psadmission.NamespaceGetter,
	podLister psadmission.PodLister,
	evaluator policy.Evaluator,
	admissionLevel psapi.Level,
) (*psadmission.Admission, error) {

	adm := &psadmission.Admission{
		Evaluator:        evaluator,
		PodSpecExtractor: &psadmission.DefaultPodSpecExtractor{},
		Configuration: &psadmissionapi.PodSecurityConfiguration{
			Defaults: psadmissionapi.PodSecurityDefaults{
				Enforce:        string(admissionLevel),
				EnforceVersion: psapi.VersionLatest,
				Audit:          string(admissionLevel),
				AuditVersion:   psapi.VersionLatest,
				Warn:           string(admissionLevel),
				WarnVersion:    psapi.VersionLatest,
			},
		},
		NamespaceGetter: nsGetter,
		PodLister:       podLister,
	}
	if err := adm.CompleteConfiguration(); err != nil {
		return nil, err
	}

	return adm, adm.ValidateConfiguration()
}

func MostRestrictivePolicyPerNamespace(results AdmissionResultsMap) map[string]psapi.Level {
	aggregatedResults := make(map[string]psapi.Level)
	for objInfo, result := range results {
		currentPolicy, ok := aggregatedResults[objInfo.Namespace]
		if !ok {
			aggregatedResults[objInfo.Namespace] = result.MostRestrictivePolicy()
		} else {
			aggregatedResults[objInfo.Namespace] = greaterPSAPrivileges(currentPolicy, result.MostRestrictivePolicy())
		}
	}
	return aggregatedResults
}

func greaterPSAPrivileges(a, b psapi.Level) psapi.Level {
	if psapiLevelIntValue(a) >= psapiLevelIntValue(b) {
		return a
	}
	return b
}

var psapiIntToLevelMapping = [4]psapi.Level{
	psapi.LevelRestricted,
	psapi.LevelBaseline,
	psapi.LevelPrivileged,
	LevelUnknown,
}

func psapiLevelIntValue(l psapi.Level) uint {
	switch l {
	case psapi.LevelPrivileged:
		return 2
	case psapi.LevelBaseline:
		return 1
	case psapi.LevelRestricted:
		return 0
	case LevelUnknown:
		fallthrough
	default:
		return 3
	}
}
