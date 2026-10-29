# Third-party software

The container includes the unmodified official Bitwarden CLI npm package,
`@bitwarden/cli` version 2026.4.2, and its dependencies. The synchronizer invokes
the CLI as a separate process. Dependency versions and integrity hashes are
recorded in `packaging/package-lock.json`.

- Source and build instructions: https://github.com/bitwarden/clients/tree/cli-v2026.4.2
- CLI documentation: https://bitwarden.com/help/cli/
- Upstream license notices: `packaging/licenses/` in this repository and
  `/usr/share/doc/home-secrets-sync/bitwarden-licenses/` in the image.

Bitwarden's default source license is GPL v3.0; its separately licensed directory
is described by the included upstream notices. Dependency license files remain
in their respective installed npm packages. Bitwarden trademarks belong to their
respective owners. This project is independent of Bitwarden and Infisical.

The runtime also includes Node.js from the official Node container image.
Node.js and Debian component notices remain at their upstream image locations.
