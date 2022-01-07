package checker

import (
	"k8s.io/client-go/kubernetes"
	psadmission "k8s.io/pod-security-admission/admission"
	psadmissionapi "k8s.io/pod-security-admission/admission/api"
	psapi "k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"
)

func SetupAdmission(kubeClient kubernetes.Interface) (*psadmission.Admission, error) {
	evaluator, err := policy.NewEvaluator(policy.DefaultChecks()) // TODO: allow experimental checks by a flag
	if err != nil {
		return nil, err
	}

	nsGetter := psadmission.NamespaceGetterFromClient(kubeClient) // to get the NS rules and possibly check for NS exemption
	podLister := psadmission.PodListerFromClient(kubeClient)      // only used while validating pods in an NS
	// FIXME: don't be static, either read from cluster, allow configuring from flags?
	//        -> the following is therefore only the default?
	// TODO: We probably want to be aware of the exemptions so we need the full config instead of just the evaluator, right?
	//		 Or maybe not, just evaluate the pod?
	adm := &psadmission.Admission{
		Evaluator:        evaluator,
		PodSpecExtractor: &psadmission.DefaultPodSpecExtractor{},
		Configuration: &psadmissionapi.PodSecurityConfiguration{
			Defaults: psadmissionapi.PodSecurityDefaults{
				Enforce:        string(psapi.LevelPrivileged),
				EnforceVersion: psapi.VersionLatest,
				Audit:          string(psapi.LevelBaseline), // TODO: so use all the different levels at once to force pod evaluation?
				AuditVersion:   psapi.VersionLatest,
				Warn:           string(psapi.LevelRestricted),
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
