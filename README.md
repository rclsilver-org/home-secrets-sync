# home-secrets-sync

Select the secrets you want to share in Vaultwarden, and deliver their values to
Infisical for your applications. Routing lives on the vault item as custom
fields; Git stores the allowed destinations and deployment configuration.

The synchronizer uses the official Bitwarden CLI to decrypt the source and
Infisical Universal Auth to access the destination. It runs once, reports
counters, and exits. The Helm chart schedules these executions without overlap.

## Select fields in Vaultwarden

Add these custom fields to a login item:

| Custom field | Value |
|---|---|
| `sync.enabled` | `true` |
| `sync.destination` | `infisical` |
| `sync.project` | `backend-secrets` |
| `sync.path` | `/aiga` |
| `sync.export.AIGA_URL` | `login.uris[0].uri` |
| `sync.export.AIGA_USERNAME` | `login.username` |
| `sync.export.AIGA_PASSWORD` | `login.password` |

Each `sync.export.<KEY>` creates a separate shared Infisical secret. Metadata
contains selectors, not duplicate secret values. `sync.destination` and
`sync.project` match aliases in the synchronizer's configuration, rather than
arbitrary URLs. An Infisical organization contains projects; the project alias
maps to its project UUID in the configuration.

`sync.environment` is optional and defaults to **`production`** when absent.
An explicitly empty environment is invalid. The selected environment and folder
must be in the configuration's allowlists. The project and environment must
already exist in Infisical; they can be provisioned with Terraform without
passing secret values through Terraform state.

Missing destination folders are created automatically in apply mode, including
intermediate folders within the allowed paths. A dry-run reports planned folder
creations without creating anything. Existing folders are reused and never
deleted. A path prefix `/aiga` allows creating that folder and its descendants,
while `/aiga-other` is excluded. Ancestors above the allowed prefix must already
exist: with prefix `/apps/aiga`, create `/apps` separately or allow `/apps` if
the synchronizer should create it too. A prefix `/` allows the whole project.
The synchronizer identity needs permission to list and create these folders.

Supported sources:

- `login.username`, `login.password` and `login.uris[N].uri` (zero-based index);
- `notes`;
- `field:CUSTOM_FIELD_NAME` for a unique, unlinked custom field.

An absent or null source blocks the run. Empty strings require an explicit
`sync.allow-empty=true` on the item. This does not permit absent sources.
Duplicate metadata, unknown `sync.*` fields on enabled items, invalid selectors
and collisions are rejected. Items are selected only by an exact
`sync.enabled=true`; disabled items and trashed items are ignored. Items requiring
master-password reprompt are rejected. Selectors are parsed without shell
execution, templates or arbitrary JSON expressions.

## Kubernetes installation

Published artifacts:

- Image: `ghcr.io/rclsilver-org/home-secrets-sync:v0.2.0`
- Chart: `oci://ghcr.io/rclsilver-org/charts/home-secrets-sync`, version `0.2.0`
- Architectures: Linux amd64 and arm64.

Create a dedicated source account with values-visible, read-only access to the
Vaultwarden collections you intend to export. In Infisical, create a machine
identity with Universal Auth and a standard write-capable project role such as
`Member`. Give application consumers their own identities with the `Viewer`
role. Server permissions remain the access-control boundary; configuration
allowlists also restrict metadata routing.

Provision an **existing Kubernetes Secret**, in the release namespace, with:

| Secret key | Purpose |
|---|---|
| `BW_CLIENTID` | Source account API client ID, typically `user.<UUID>` |
| `BW_CLIENTSECRET` | Source account API client secret |
| `BW_PASSWORD` | Source account master password for local decryption |
| `INFISICAL_CLIENT_ID` | Synchronizer machine identity client ID |
| `INFISICAL_CLIENT_SECRET` | Universal Auth client secret |

The API key does not replace the Vaultwarden master password. Encrypt this
bootstrap Secret with your SOPS policy and decrypt directly into Kubernetes.
Keep values out of chat, shell arguments, Helm values and Terraform state. The
chart references the Secret without creating it or storing its values in the
Helm release. Other destinations may use different environment variable names
through `clientIDEnv` and `clientSecretEnv`.

Prepare `values.yaml` using the chart's documented defaults. Replace the example
URLs and project UUID, set `existingSecret`, and narrow `config` allowlists.
The chart injects its own runtime directory and bundled CLI path.

```sh
helm upgrade --install secrets-sync \
  oci://ghcr.io/rclsilver-org/charts/home-secrets-sync \
  --version 0.2.0 --namespace secrets --create-namespace \
  --values values.yaml --wait

# Defaults: suspended, dryRun=true. Review a manual dry-run first.
kubectl -n secrets create job --from=cronjob/secrets-sync-home-secrets-sync sync-review
kubectl -n secrets logs -f job/sync-review
```

After reviewing the run, enable `dryRun: false` and `suspend: false` in your
values and upgrade the release. By default, it runs every five minutes in UTC,
with `concurrencyPolicy: Forbid`, no automatic Job retries, and a six-minute
deadline. Run **one release/writer for a given destination scope**; manual Jobs
and distinct releases can still overlap. Space authentication attempts to
respect your Vaultwarden login limits.

The Pod runs as UID/GID 10001, with a read-only root filesystem, no capabilities,
no service account token, and a private runtime directory on a memory-backed
`emptyDir`. No PVC is required. Network access is needed to DNS, Vaultwarden and
Infisical only. Configure `podLabels` and the optional `networkPolicy.egress`
rules for your cluster; enabling that policy with no rules denies all traffic.
No Service, ingress, cluster-level RBAC or public endpoint is created.

`image.digest` can pin an immutable image instead of a tag. For an internal CA,
set `caConfigMap` to an existing ConfigMap containing its public `ca.crt` bundle.
This extends the CLI's trust and combines your bundle with the image's system
roots for Go. Certificate verification stays enabled. Avoid plaintext swap and
memory dumps on the execution node.

See [chart values](charts/home-secrets-sync/values.yaml) and its
[schema](charts/home-secrets-sync/values.schema.json) for deployment options.

## Standalone execution

The image includes the official `bw` CLI (2026.4.2), Node.js and the synchronizer.
Inject credentials through your runtime's secret mechanism, mount a read-only
configuration based on [config.example.json](config.example.json), and provide a
private tmpfs runtime directory. The chart performs this setup automatically.

```sh
home-secrets-sync -config config.json          # dry-run
home-secrets-sync -config config.json -apply   # write differences
home-secrets-sync -version
```

The source CLI gets a new private profile each time: API-key login, master
password unlock, vault sync, item read, then logout and profile removal. Existing
personal CLI profiles and inherited `BW_SESSION` are not used. Disk-backed
runtime directories are refused. Credentials are passed to child processes
through the environment, never command arguments. Decrypted values are held in
memory and are not written to an intermediate file.

Output is a JSON summary containing `mode`, `exports`, `create`, `update`,
`unchanged`, `written`, `foldersCreate` (planned) and `foldersCreated` (confirmed
creations in this run). Errors identify source or target indexes with
controlled messages; CLI diagnostics and server response bodies are suppressed.
No item names, IDs or secret values are logged. Exit status 0 means success,
1 means failure, and 2 means invalid arguments. A run has a five-minute context
deadline; individual HTTP requests and CLI commands have shorter timeouts.

## Update and ownership rules

Every selected export and destination is checked before the first write,
including folder creation. A dry-run authenticates and compares current
destination values but does not create folders or create or update secrets.
Imported secrets and reference expansion are disabled
for comparisons. Multiline values are transmitted literally.

The synchronizer owns a destination secret through a stable comment:
`vaultwarden-sync:v1:<sourceID>:<itemID>:<KEY>`. An existing secret without the
expected marker blocks the whole run, even if its value matches. There is no
automatic adoption. Keep `sourceID` and these comments stable. This marker
prevents accidental overwrites; it does not replace Infisical permissions.

Unchanged values are left alone, preserving their Infisical version. Values
changed in Vaultwarden update the corresponding managed secrets. **Nothing is
automatically deleted**, including when an item is disabled, renamed, moved or
removed. Review consumers before manually removing an old destination.

Folder creations and secret writes are individual API operations, not a
transaction across all exports. All planned folders are created before secret
writes begin. If a folder creation fails, earlier folder creations remain and
no secret writes begin; replaying reuses those folders. No folders are removed
when exports are disabled or moved.
The destination is read again before writing to detect intervening edits, but
the API has no atomic compare-and-swap for this operation. Use a single writer.
A transport failure may occur after a write committed but before it was
acknowledged. Replaying converges through the ownership and value checks;
confirmed partial progress is included in write-failure diagnostics.

## Development and releases

Go 1.26+ and Docker Compose are required. Helm, kubectl and jq are needed for
chart checks. The Go module has no external dependencies. The image uses pinned
base digests and a committed npm lockfile; npm install scripts are disabled.
Dependency update tooling must refresh the lockfile deliberately.

```sh
make test vet
make image
# Set both scratch variables to permitted private directories first.
make integration
make chart-test
```

The integration test creates its own Vaultwarden, Infisical, PostgreSQL and Redis
on an internal Docker network, with no published ports. All accounts and values
are synthetic, and server data is ephemeral. It exercises the **built image**,
including its bundled CLI, API-key unlock, exports, default environment,
idempotence, rotation, Viewer access, collision and ownership refusal, missing
sources, allowlists, no deletion and output redaction. Test state stays in RAM;
only a public development CA certificate is copied to the host scratch. The
development login limiter is deliberately relaxed for repeated test logins.

CI additionally runs race tests, renders the chart, checks its credential schema,
and installs it on a disposable kind cluster to exercise its secured Pod and RAM
volume. Branch and pull request builds verify only. A semantic `vX.Y.Z` tag
publishes the image, chart and GitHub release after all checks pass. Bump both
`Chart.version` (`X.Y.Z`) and `Chart.appVersion` (`vX.Y.Z`) before tagging.
`latest` moves only on releases. Actions are pinned by commit and publication
permissions are limited to the release job.

See [third-party notices](THIRD_PARTY_NOTICES.md) for the embedded official CLI.
