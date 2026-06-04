VERSION ?= $(shell cat VERSION)
IMAGE_REPOSITORY ?= ghcr.io/hjames9/oci-cas-issuer
IMAGE_TAG ?= $(VERSION)-controller
IMG ?= $(IMAGE_REPOSITORY):$(IMAGE_TAG)
CHART := charts/oci-cas-issuer
CHART_VERSION ?= $(VERSION)
CHART_PACKAGE_DIR ?= dist/charts
CHART_PACKAGE := $(CHART_PACKAGE_DIR)/oci-cas-issuer-$(CHART_VERSION).tgz
HELM_CHART_REPOSITORY ?=
CONTROLLER_GEN ?= ./bin/controller-gen
CONTROLLER_GEN_VERSION ?= v0.16.5
GOLANGCI_LINT ?= ./bin/golangci-lint
GOLANGCI_LINT_VERSION ?= v1.64.8
GEN_GOCACHE ?= /tmp/oci-cas-issuer-controller-gen-cache
LINT_GOCACHE ?= /tmp/oci-cas-issuer-lint-go-cache

.PHONY: build test coverage lint manifests generate docker-build docker-push helm-lint helm-package helm-push

build:
	go build -buildvcs=false ./cmd/manager

test:
	go test ./...

coverage:
	./hack/coverage.sh

lint: $(GOLANGCI_LINT)
	GOCACHE=$(LINT_GOCACHE) $(GOLANGCI_LINT) run

$(GOLANGCI_LINT):
	GOBIN=$(CURDIR)/bin go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(CONTROLLER_GEN):
	GOBIN=$(CURDIR)/bin go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

manifests: $(CONTROLLER_GEN)
	GOCACHE=$(GEN_GOCACHE) $(CONTROLLER_GEN) crd paths="./api/..." output:crd:artifacts:config=$(CHART)/crds

generate: $(CONTROLLER_GEN)
	GOCACHE=$(GEN_GOCACHE) $(CONTROLLER_GEN) object paths="./api/..."

docker-build:
	docker buildx build --provenance=false --platform linux/amd64,linux/arm64 -t $(IMG) .

docker-push:
	docker buildx build --provenance=false --platform linux/amd64,linux/arm64 -t $(IMG) --push .

helm-lint:
	helm lint $(CHART)

helm-package:
	mkdir -p $(CHART_PACKAGE_DIR)
	helm package $(CHART) --destination $(CHART_PACKAGE_DIR) --version $(CHART_VERSION) --app-version $(CHART_VERSION)

helm-push: helm-package
	@test -n "$(HELM_CHART_REPOSITORY)" || (echo "Set HELM_CHART_REPOSITORY=oci://registry/namespace/path" >&2; exit 1)
	helm push $(CHART_PACKAGE) $(HELM_CHART_REPOSITORY)
