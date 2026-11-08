# SBOM fixtures

Real CycloneDX and SPDX documents produced by the generators, used by the inventory tests. Each
sample project pins a few old package versions that have known vulnerabilities.

| File | Generator | Command |
| --- | --- | --- |
| `cargo-cyclonedx.json` | cargo-cyclonedx 0.5.9 | `cargo cyclonedx --format json --spec-version 1.5` on a crate depending on `smallvec =1.6.0` and `itoa 1` |
| `cyclonedx-npm.json` | @cyclonedx/cyclonedx-npm 6.0.1 | `cyclonedx-npm --package-lock-only --spec-version 1.6` on a package depending on `lodash 4.17.20`, `minimist 1.2.5` and `@babel/helper-string-parser 7.25.9` |
| `cyclonedx-py.json` | cyclonedx-py (cyclonedx-bom 8.0.1) | `uv sync`, then `cyclonedx-py environment .venv --spec-version 1.6` on a uv project depending on `urllib3 ==1.26.4` and `idna ==3.6` |
| `syft.json` | Syft 1.57.0 | `syft scan dir:rootfs -o cyclonedx-json@1.6` on the Alpine 3.19.0 minimal root filesystem, as it would scan a container image |
| `syft-spdx.json` | Syft 1.33.0 | `syft scan registry:alpine:3.19.0 --platform linux/amd64 -o spdx-json` (SPDX 2.3) |
| `syft-cargo-spdx-2.2.json` | Syft 1.33.0 | `syft scan dir:cargo-scan -o spdx-json@2.2` on a directory holding the `Cargo.toml` and `Cargo.lock` of a crate depending on `smallvec =1.6.0` and `regex =1.5.4` |
| `trivy-npm-spdx.json` | Trivy 0.76.2 | `trivy fs --format spdx-json npm-sample` (SPDX 2.3) on a package depending on `lodash 4.17.20`, `minimist 1.2.5`, `@babel/helper-string-parser 7.25.9` and `debug 2.6.8`, with its `package-lock.json` only |
| `github-dependency-graph.json` | GitHub dependency graph | `gh api repos/sharkdp/hexyl/dependency-graph/sbom --jq .sbom` (SPDX 2.3), the document unwrapped from the API's response and indented; a public Rust repository whose `Cargo.lock` GitHub exports as a flat list, with GitHub Actions pinned to version requirements |

The local path of the Rust sample project was replaced with `/workspace/fixture-cargo`.
