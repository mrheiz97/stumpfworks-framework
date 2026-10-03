# Releases

Stable releases are created only from `main`. The release workflow rejects a
tag when its commit is not contained in `main`, the tag is lightweight, or
GitHub does not verify its signature.

## Release procedure

1. Merge the tested release candidate from `develop` into `main`.
2. Confirm that CI is green and the changelog describes the release.
3. Create and push a signed annotated semantic-version tag, for example
   `v0.4.0-alpha.1`.
4. Wait for the `Release` workflow and verify the published checksums and
   attestations before announcing the release.

The workflow reruns formatting, module verification, vet, race tests, builds and
the vulnerability scan. It publishes a reproducible source archive, a
CycloneDX JSON SBOM and SHA-256 checksums. GitHub's keyless Sigstore integration
signs provenance and SBOM attestations; no persistent signing secret is stored
in the repository.

Consumers can verify a downloaded artifact with GitHub CLI:

```sh
gh attestation verify stumpfworks-framework-v0.4.0.tar.gz \
  --repo mrheiz97/stumpfworks-framework
sha256sum --check SHA256SUMS
```

Creating a version tag is intentionally a manual release gate. Pushing an
unsigned tag or a tag outside `main` must fail without publishing a release.
