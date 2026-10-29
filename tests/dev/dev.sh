#!/usr/bin/env bash
set -euo pipefail
dev_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
compose=(docker compose --progress quiet -p home-secrets-sync-dev -f "$dev_dir/compose.yaml")
case "${1:-status}" in
  up)
    "${compose[@]}" up -d --wait --wait-timeout 300
    ;;
  bootstrap)
    test "$(docker network inspect home-secrets-sync-dev_default --format '{{.Internal}}')" = true
    scratch=${SECRETS_SYNC_DEV_SCRATCH:?Set SECRETS_SYNC_DEV_SCRATCH to your permitted private scratch directory}
    mkdir -p "$scratch"
    "${compose[@]}" exec -T vaultwarden cat /data/dev-tls.crt > "$scratch/secrets-sync-dev-vaultwarden.crt"
    "${compose[@]}" exec -T infisical sh -c 'cat > /scratch/vaultwarden.crt' < "$scratch/secrets-sync-dev-vaultwarden.crt"
    "${compose[@]}" exec -T -e NODE_EXTRA_CA_CERTS=/scratch/vaultwarden.crt infisical node --input-type=module < "$dev_dir/bootstrap.mjs"
    ;;
  status)
    "${compose[@]}" ps
    ;;
  down)
    "${compose[@]}" down
    ;;
  *)
    printf 'Usage: bash dev.sh {up|bootstrap|status|down}\n' >&2
    exit 2
    ;;
esac
