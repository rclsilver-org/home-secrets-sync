#!/usr/bin/env bash
# CI only. Never run against an existing or production Kubernetes context.
set -euo pipefail
test "$(kubectl config current-context)" = kind-home-secrets-sync-test
test "${CI:-}" = true
scratch=${SYNC_SCRATCH:?Set a permitted scratch directory}
image=${SYNC_TEST_IMAGE:-home-secrets-sync:dev}
kind load docker-image "$image" --name home-secrets-sync-test
kubectl create namespace chart-test
kubectl -n chart-test create secret generic home-secrets-sync-credentials \
  --from-literal=BW_CLIENTID=synthetic --from-literal=BW_CLIENTSECRET=synthetic \
  --from-literal=BW_PASSWORD=synthetic --from-literal=INFISICAL_CLIENT_ID=synthetic \
  --from-literal=INFISICAL_CLIENT_SECRET=synthetic
helm install smoke charts/home-secrets-sync -n chart-test \
  --set image.repository=home-secrets-sync --set image.tag=dev --set image.pullPolicy=Never --wait
# Keep the rendered Pod's security context, volumes, Secret and initialization.
# Only replace the final command so the smoke test needs no real credentials.
kubectl -n chart-test create job --from=cronjob/smoke-home-secrets-sync smoke --dry-run=client -o json |
  jq '.spec.template.spec.containers[0].args[0] |= sub("exec /usr/local/bin/home-secrets-sync.*"; "test -w /run/home-secrets-sync/private; /usr/local/bin/bw --version; exec /usr/local/bin/home-secrets-sync -version")' > "$scratch/chart-smoke-job.json"
kubectl create -f "$scratch/chart-smoke-job.json"
if ! kubectl -n chart-test wait --for=condition=complete job/smoke --timeout=180s; then
  kubectl -n chart-test describe job smoke
  kubectl -n chart-test logs job/smoke || true
  exit 1
fi
kubectl -n chart-test logs job/smoke
