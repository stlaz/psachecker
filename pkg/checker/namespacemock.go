package checker

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	psadmission "k8s.io/pod-security-admission/admission"
)

type namespaceGetterFunc func(ctx context.Context, name string) (namespace *corev1.Namespace, err error)

func (f namespaceGetterFunc) GetNamespace(ctx context.Context, name string) (namespace *corev1.Namespace, err error) {
	return f(ctx, name)
}

func knowAllNamespaceGetter(_ context.Context, name string) (namespace *corev1.Namespace, err error) {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: make(map[string]string),
		},
	}, nil
}

var KnowAllNamespaceGetter psadmission.NamespaceGetter = namespaceGetterFunc(knowAllNamespaceGetter)
