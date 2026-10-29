SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
IMAGE ?= home-secrets-sync:dev
VERSION ?= dev
REVISION ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

.PHONY: test vet image integration chart-test
test:
	CGO_ENABLED=0 go test ./...
vet:
	CGO_ENABLED=0 go vet ./...
image:
	docker build --build-arg VERSION=$(VERSION) --build-arg REVISION=$(REVISION) -t $(IMAGE) .
integration:
	SYNC_TEST_IMAGE=$(IMAGE) bash tests/dev/run.sh
chart-test:
	bash tests/chart.sh
