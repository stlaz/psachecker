package checker

import (
	"context"
	"fmt"
	"sync"

	admissionv1 "k8s.io/api/admission/v1"
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

func NewParallelAdmission(kubeClient kubernetes.Interface, nsGetter psadmission.NamespaceGetter) (*ParallelAdmission, error) {
	evaluator, err := policy.NewEvaluator(policy.DefaultChecks()) // TODO: allow experimental checks by a flag
	if err != nil {
		return nil, err
	}

	podLister := psadmission.PodListerFromClient(kubeClient) // only used while validating pods in an NS

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
