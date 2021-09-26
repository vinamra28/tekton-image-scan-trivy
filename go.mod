module github.com/vinamra28/tekton-trivy

go 1.14

require (
	github.com/aquasecurity/fanal v0.0.0-20210520034323-54c5a82e861f
	github.com/aquasecurity/trivy v0.18.3
	github.com/aquasecurity/trivy-db v0.0.0-20210429114658-ae22941a55d0
	github.com/google/go-containerregistry v0.6.0
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	github.com/tektoncd/pipeline v0.15.2
	go.uber.org/zap v1.19.0
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	gotest.tools v2.2.0+incompatible
	gotest.tools/v3 v3.0.3
	k8s.io/apimachinery v0.20.6
	k8s.io/client-go v11.0.1-0.20190805182717-6502b5e7b1b5+incompatible
	knative.dev/pkg v0.0.0-20200702222342-ea4d6e985ba0
)

// Pin k8s deps to 1.17.6
replace (
	k8s.io/api => k8s.io/api v0.17.6
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.17.6
	k8s.io/apimachinery => k8s.io/apimachinery v0.17.6
	k8s.io/apiserver => k8s.io/apiserver v0.17.6
	k8s.io/client-go => k8s.io/client-go v0.17.6
	k8s.io/code-generator => k8s.io/code-generator v0.17.6
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20200410145947-bcb3869e6f29
)
