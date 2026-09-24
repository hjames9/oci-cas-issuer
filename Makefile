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

.PHONY: help build test coverage lint install-golangci-lint install-controller-gen manifests generate docker-build docker-push helm-lint helm-package helm-push require-release-version release-prepare release-check release-commit release-tag release-watch release

help: ## Show available Make targets.
	@awk 'BEGIN {FS = ":.*##"; printf "Available targets:\n"} /^[a-zA-Z0-9_.%$$()\/-]+:.*##/ {printf "  %-24s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the controller manager binary.
	go build -buildvcs=false ./cmd/manager

test: ## Run all Go tests.
	go test ./...

coverage: ## Run coverage checks and enforce the configured coverage threshold.
	./hack/coverage.sh

lint: $(GOLANGCI_LINT) ## Run golangci-lint.
	GOCACHE=$(LINT_GOCACHE) $(GOLANGCI_LINT) run

install-golangci-lint: $(GOLANGCI_LINT) ## Install golangci-lint into ./bin.

$(GOLANGCI_LINT):
	GOBIN=$(CURDIR)/bin go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

install-controller-gen: $(CONTROLLER_GEN) ## Install controller-gen into ./bin.

$(CONTROLLER_GEN):
	GOBIN=$(CURDIR)/bin go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

manifests: $(CONTROLLER_GEN) ## Generate CRD manifests into the Helm chart.
	GOCACHE=$(GEN_GOCACHE) $(CONTROLLER_GEN) crd paths="./api/..." output:crd:artifacts:config=$(CHART)/crds

generate: $(CONTROLLER_GEN) ## Generate Kubernetes deepcopy code.
	GOCACHE=$(GEN_GOCACHE) $(CONTROLLER_GEN) object paths="./api/..."

docker-build: ## Build the multi-arch controller image.
	docker buildx build --provenance=false --platform linux/amd64,linux/arm64 -t $(IMG) .

docker-push: ## Build and push the multi-arch controller image.
	docker buildx build --provenance=false --platform linux/amd64,linux/arm64 -t $(IMG) --push .

helm-lint: ## Lint the Helm chart.
	helm lint $(CHART)

helm-package: ## Package the Helm chart into dist/charts.
	mkdir -p $(CHART_PACKAGE_DIR)
	helm package $(CHART) --destination $(CHART_PACKAGE_DIR) --version $(CHART_VERSION) --app-version $(CHART_VERSION)

helm-push: helm-package ## Package and push the Helm chart to HELM_CHART_REPOSITORY.
	@test -n "$(HELM_CHART_REPOSITORY)" || (echo "Set HELM_CHART_REPOSITORY=oci://registry/namespace/path" >&2; exit 1)
	helm push $(CHART_PACKAGE) $(HELM_CHART_REPOSITORY)

require-release-version: ## Validate that VERSION was explicitly supplied and is semver.
	@test "$(origin VERSION)" = "command line" -o "$(origin VERSION)" = "environment" -o "$(origin VERSION)" = "environment override" || (echo "Set VERSION explicitly, for example: make release VERSION=0.1.18" >&2; exit 1)
	@test -n "$(VERSION)" || (echo "Set VERSION, for example: make release VERSION=0.1.18" >&2; exit 1)
	@printf '%s\n' "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$$' || (echo "VERSION must be semver without a leading v, got $(VERSION)" >&2; exit 1)

release-prepare: require-release-version ## Update version files for a release.
	printf '%s\n' "$(VERSION)" > VERSION
	sed -i 's/^version: .*/version: $(VERSION)/' $(CHART)/Chart.yaml
	sed -i 's/^appVersion: .*/appVersion: $(VERSION)/' $(CHART)/Chart.yaml
	sed -i 's/^  tag: .*/  tag: $(VERSION)-controller/' $(CHART)/values.yaml

release-check: require-release-version ## Run release validation checks.
	$(MAKE) test helm-lint helm-package VERSION=$(VERSION) CHART_VERSION=$(VERSION)

release-commit: require-release-version ## Commit release version file changes.
	git add VERSION $(CHART)/Chart.yaml $(CHART)/values.yaml
	git commit -m "chore: release $(VERSION)"

release-tag: require-release-version ## Tag the release and push main plus the tag.
	@test "$$(git branch --show-current)" = "main" || (echo "Release tags must be pushed from main" >&2; exit 1)
	git tag v$(VERSION)
	git push origin main
	git push origin v$(VERSION)

release-watch: require-release-version ## Watch the GitHub Actions release workflow for the release tag.
	@echo "Waiting for GitHub Actions release workflow for v$(VERSION)..."
	@run_id=""; \
	for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do \
		run_id=$$(gh run list --workflow release.yaml --branch v$(VERSION) --event push --limit 1 --json databaseId --jq '.[0].databaseId // ""'); \
		if [ -n "$$run_id" ]; then break; fi; \
		sleep 3; \
	done; \
	test -n "$$run_id" || (echo "Could not find release workflow run for v$(VERSION)" >&2; exit 1); \
	gh run watch "$$run_id" --exit-status

release: release-prepare release-check release-commit release-tag release-watch ## Prepare, validate, commit, tag, push, and watch a release.
