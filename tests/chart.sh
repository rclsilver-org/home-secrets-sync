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
  --set config.vaultwarden.deviceID=0b2c5a40-1f0e-4a33-9c11-6d2f7e8a9b10 \
  --set image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa > "$scratch/chart-apply.yaml"
"$helm_bin" template test "$chart_dir" --set persistence.existingClaim=my-claim > "$scratch/chart-claim.yaml"
# Client-side conversion only; KUBECONFIG may point at a disposable CI cluster.
# Cluster discovery is read-only. No object is created by this script.
for mode in default apply claim; do
  kubectl --cache-dir "$scratch/kube-cache" create --dry-run=client --validate=false \
    -f "$scratch/chart-$mode.yaml" -o json | jq -s . > "$scratch/chart-$mode.json"
done
jq -e '
  (map(select(.kind=="Deployment"))[0]) as $d |
  ($d.spec.template.spec) as $pod |
  (map(select(.kind=="ConfigMap"))[0].data["config.json"] | fromjson) as $config |
  $d.spec.replicas == 0 and $d.spec.strategy.type == "Recreate" and
  $pod.automountServiceAccountToken == false and
  $pod.securityContext.runAsNonRoot == true and
  $pod.containers[0].securityContext.readOnlyRootFilesystem == true and
  $pod.containers[0].envFrom[0].secretRef.name == "home-secrets-sync-credentials" and
  ($pod.containers[0].args[0] | contains("-interval 5m")) and
  ($pod.containers[0].args[0] | contains("-apply") | not) and
  any($pod.volumes[]; .emptyDir.medium=="Memory") and
  any($pod.volumes[]; .name=="state" and .persistentVolumeClaim.claimName=="test-home-secrets-sync") and
  any(.[]; .kind=="PersistentVolumeClaim" and .spec.accessModes==["ReadWriteOnce"]) and
  all(.[]; .kind!="CronJob") and
  $config.vaultwarden.runtimeDir == "/run/home-secrets-sync/private" and
  $config.vaultwarden.stateDir == "/var/lib/home-secrets-sync" and
  $config.vaultwarden.binary == "/usr/local/bin/bw" and
  all(.[]; .kind!="Secret")' "$scratch/chart-default.json" > /dev/null
jq -e '
  (map(select(.kind=="Deployment"))[0]) as $d |
  (map(select(.kind=="ConfigMap"))[0].data["config.json"] | fromjson) as $config |
  $d.spec.replicas == 1 and
  ($d.spec.template.spec.containers[0].args[0] | contains(" -apply")) and
  ($d.spec.template.spec.containers[0].args[0] | contains("NODE_EXTRA_CA_CERTS")) and
  ($d.spec.template.spec.containers[0].image | contains("@sha256:")) and
  $config.vaultwarden.deviceID == "0b2c5a40-1f0e-4a33-9c11-6d2f7e8a9b10" and
  any(.[]; .kind=="NetworkPolicy" and .spec.ingress==[] and .spec.egress==[])' "$scratch/chart-apply.json" > /dev/null
jq -e '
  all(.[]; .kind!="PersistentVolumeClaim") and
  any(.[]; .kind=="Deployment" and any(.spec.template.spec.volumes[]; .persistentVolumeClaim.claimName=="my-claim"))' "$scratch/chart-claim.json" > /dev/null
# Refuse accidental plaintext credentials in chart values.
if "$helm_bin" template test "$chart_dir" --set config.vaultwarden.password=must-not-be-accepted > /dev/null 2>&1; then
  printf 'Chart unexpectedly accepts a plaintext password value.\n' >&2
  exit 1
fi
printf 'PASS: Helm schema, suspended dry-run daemon defaults, apply mode, RAM and PVC volumes, Secret reference, custom CA, digest pin and deny-all policy.\n'
