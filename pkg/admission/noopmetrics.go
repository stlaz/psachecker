package admission

import (
	psapi "k8s.io/pod-security-admission/api"
	psmetrics "k8s.io/pod-security-admission/metrics"
)

type NoopMetricsRecorder struct{}

var _ psmetrics.Recorder = &NoopMetricsRecorder{}

func (r *NoopMetricsRecorder) RecordEvaluation(
	psmetrics.Decision,
	psapi.LevelVersion,
	psmetrics.Mode,
	psapi.Attributes) {
}
func (r *NoopMetricsRecorder) RecordExemption(psapi.Attributes)               {}
func (r *NoopMetricsRecorder) RecordError(fatal bool, attrs psapi.Attributes) {}
