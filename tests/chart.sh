#!/usr/bin/env bash
set -euo pipefail
chart_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../charts/home-secrets-sync" && pwd)
scratch=${SYNC_SCRATCH:?Set a permitted scratch directory}
helm_bin=${HELM:-helm}
mkdir -p "$scratch"
"$helm_bin" lint "$chart_dir"
"$helm_bin" template test "$chart_dir" > "$scratch/chart-default.yaml"
"$helm_bin" template test "$chart_dir" --set dryRun=false --set suspend=false \
  --set caConfigMap=test-ca --set networkPolicy.enabled=true \
  --set image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa > "$scratch/chart-apply.yaml"
# Client-side conversion only; KUBECONFIG may point at a disposable CI cluster.
# Cluster discovery is read-only. No object is created by this script.
for mode in default apply; do
  kubectl --cache-dir "$scratch/kube-cache" create --dry-run=client --validate=false \
    -f "$scratch/chart-$mode.yaml" -o json | jq -s . > "$scratch/chart-$mode.json"
done
jq -e '
  (map(select(.kind=="CronJob"))[0]) as $job |
  (map(select(.kind=="ConfigMap"))[0].data["config.json"] | fromjson) as $config |
  $job.spec.suspend == true and $job.spec.concurrencyPolicy == "Forbid" and
  $job.spec.jobTemplate.spec.backoffLimit == 0 and
  $job.spec.jobTemplate.spec.template.spec.automountServiceAccountToken == false and
  $job.spec.jobTemplate.spec.template.spec.securityContext.runAsNonRoot == true and
  $job.spec.jobTemplate.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem == true and
  $job.spec.jobTemplate.spec.template.spec.containers[0].envFrom[0].secretRef.name == "home-secrets-sync-credentials" and
  ($job.spec.jobTemplate.spec.template.spec.containers[0].args[0] | contains("-apply") | not) and
  any($job.spec.jobTemplate.spec.template.spec.volumes[]; .emptyDir.medium=="Memory") and
  $config.vaultwarden.runtimeDir == "/run/home-secrets-sync/private" and
  $config.vaultwarden.binary == "/usr/local/bin/bw" and
  all(.[]; .kind!="Secret")' "$scratch/chart-default.json" > /dev/null
jq -e '
  (map(select(.kind=="CronJob"))[0]) as $job |
  $job.spec.suspend == false and
  ($job.spec.jobTemplate.spec.template.spec.containers[0].args[0] | contains(" -apply")) and
  ($job.spec.jobTemplate.spec.template.spec.containers[0].args[0] | contains("NODE_EXTRA_CA_CERTS")) and
  ($job.spec.jobTemplate.spec.template.spec.containers[0].image | contains("@sha256:")) and
  any(.[]; .kind=="NetworkPolicy" and .spec.ingress==[] and .spec.egress==[])' "$scratch/chart-apply.json" > /dev/null
# Refuse accidental plaintext credentials in chart values.
if "$helm_bin" template test "$chart_dir" --set config.vaultwarden.password=must-not-be-accepted > /dev/null 2>&1; then
  printf 'Chart unexpectedly accepts a plaintext password value.\n' >&2
  exit 1
fi
printf 'PASS: Helm schema, suspended dry-run defaults, apply mode, RAM volume, Secret reference, custom CA, digest pin and deny-all policy.\n'
