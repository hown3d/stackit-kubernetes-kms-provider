REGISTRY ?= ko.local

kind-up: kind load-image

kind-down:
	kind delete cluster

kind:
	cd test && kind create cluster --config kind-config.yaml

stream-kms-plugin-logs:
	docker exec -t kind-control-plane sh -c 'crictl logs -f $$(crictl ps -a --name kms --output json | jq -r ".containers[].id")'

image:
	KO_DOCKER_REPO=$(REGISTRY)/stackitcloud/kubernetes-kms-plugin ko build --bare --platform=linux/amd64,linux/arm64 --push=false --sbom=none .

load-image: image
	while ! kind get kubeconfig >/dev/null 2>&1; do \
      echo "kind not running..." ; \
      sleep 1; \
    done
	kind load docker-image ko.local/stackitcloud/kubernetes-kms-plugin

.PHONY: test
test:
	go test ./...