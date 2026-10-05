# Ordinary SBOM pilot fixture

This non-production package pins intentionally vulnerable `lodash@4.17.20` to
exercise advisory matching from an ordinary SBOM with no embedded vulnerability
section. The generated JSON is authentic Syft output and is retained byte for
byte. The fixture packages are never executed.

Generated on 2026-10-02 with official [Syft v1.54.0](https://github.com/anchore/syft/releases/tag/v1.54.0),
Git commit `cc326e45a6213360266dda4b30cc68095946d676`, on darwin/arm64.
The downloaded `syft_1.54.0_darwin_arm64.tar.gz` SHA-256 is
`7e0bdad94c569fc6d5785c9a657bbae3d4c4e140ccb5eace3d0b5b6bc2b6dbcf`;
it matched both the official release asset digest and release checksum file.

The package-lock SHA-256 is
`60ce9f7cb608cf4173dbd4bf2673daf16a986c10017e995bf35f1e8fa2fa73ce`.
The retained `sbom.cdx.json` SHA-256 is
`d4362c63339a4de190d318f89fd0a202b59758fdd41b085fbb3473e64ee93342`
(3,211 bytes, CycloneDX 1.6, two package components, zero embedded vulnerabilities).

Generation used these commands from a separate directory containing only the
package/lock and installed fixture. Substitute the verified Syft executable path:

```sh
rtk proxy npm ci --ignore-scripts --no-audit --no-fund
rtk proxy env SYFT_FILE_METADATA_SELECTION=none SYFT_CHECK_FOR_APP_UPDATE=false \
  syft scan dir:. --base-path . --source-name custos-ordinary-sbom-pilot \
  --source-version 1.0.0 --output cyclonedx-json@1.6=../sbom.cdx.json
```

`file.metadata.selection=none` prevents file metadata from carrying private
absolute paths; package identities, versions, package URLs and dependency edges
come from the real lockfile cataloger. The output was inspected for private paths
and secrets before publication. No generated JSON was hand edited. Serial number
and timestamp vary on regeneration; the stored hash binds this exact fixture.

Use an immutable Git commit URL as the configured collector target. Keep the
standard public-destination policy enabled. The operational receipt is in
[the Custos pilot receipt](https://github.com/brianluby/custos/pull/43). This public mirror supports Custos #115 / ID1364 and sibling #134 / ID1383; it changes no library behavior or dependency pins.
