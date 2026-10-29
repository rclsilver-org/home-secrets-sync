#!/usr/bin/env bash
# Exercises the exact built image; all accounts and data are disposable fixtures.
set -euo pipefail
umask 077
dev_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scratch=${SECRETS_SYNC_DEV_SCRATCH:?Set a permitted private scratch directory}
image=${SYNC_TEST_IMAGE:-home-secrets-sync:dev}
compose=(docker compose --progress quiet -p home-secrets-sync-dev -f "$dev_dir/compose.yaml")
mkdir -p "$scratch"
cleanup() { if test "${KEEP_DEV_STACK:-false}" != true; then "${compose[@]}" down; fi; }
trap cleanup EXIT
"${compose[@]}" up -d --wait --wait-timeout 300
bash "$dev_dir/dev.sh" bootstrap
test "$(docker network inspect home-secrets-sync-dev_default --format '{{.Internal}}')" = true
vw_container=$("${compose[@]}" ps -q vaultwarden)
infisical_container=$("${compose[@]}" ps -q infisical)
address=$(docker inspect --format '{{with index .NetworkSettings.Networks "home-secrets-sync-dev_default"}}{{.IPAddress}}{{end}}' "$vw_container")
docker exec "$vw_container" cat /data/dev-tls.crt > "$scratch/vaultwarden.crt"
# This is a public CA certificate, read by the image's non-root UID.
chmod 0644 "$scratch/vaultwarden.crt"
docker exec "$infisical_container" cat /scratch/dev-bootstrap.json |
  docker run --rm -i --network home-secrets-sync-dev_default --read-only --user 10001:10001 \
    --cap-drop ALL --security-opt no-new-privileges:true --memory 1g --cpus 2 --pids-limit 128 \
    --tmpfs /scratch:uid=10001,gid=10001,mode=0700,size=128m \
    --mount "type=bind,src=$scratch/vaultwarden.crt,dst=/dev-ca.crt,readonly" \
    --mount "type=bind,src=$dev_dir/test-sync.mjs,dst=/test-sync.mjs,readonly" \
    -e DEVELOPMENT_FIXTURES_ONLY=true -e NODE_EXTRA_CA_CERTS=/dev-ca.crt -e "DEV_VAULTWARDEN_URL=https://$address:8443" \
    --entrypoint node "$image" /test-sync.mjs
