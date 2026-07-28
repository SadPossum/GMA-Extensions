# Support Policy

## Release Channels

The `dev` branch is GMA Extensions's changing integration line. Workflow-dispatch runs create reviewable candidate evidence, but they are not supported releases.

| Channel | Status |
| --- | --- |
| `dev` | Pre-release integration |
| Tagged production release | None yet |

## Compatibility

A release contains the owned repository source archive, release manifest, checksums, CycloneDX SBOM, and GitHub attestations.

Pre-1.0 releases may contain breaking changes between minor versions. Compatibility promises belong to each repository and its tagged release notes; composition repositories do not replace those contracts.

## End Of Life

Only `dev` and the current tagged release receive fixes during the pre-1.0 period. Older tags are end of life when a newer tag is published unless a release note explicitly states otherwise.

## Support

Security reports follow `SECURITY.md`. Maintenance is best effort and has no contractual support SLA.
