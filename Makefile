REGISTRY ?= ttl.sh

kind:
	cd test && kind create cluster --config kind-config.yaml

test-key:
	./scripts/testkey.sh

stream-kms-plugin-logs:
	docker exec -t kind-control-plane sh -c 'crictl logs -f $$(crictl ps -a --name kms --output json | jq -r ".containers[].id")'

image:
		KO_DOCKER_REPO=$(REGISTRY)/stackitcloud/kubernetes-kms-plugin ko build --bare --sbom=none .
