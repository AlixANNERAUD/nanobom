# Releasing

Releases are automated with [release-plz](https://release-plz.dev) through a release pull
request. nanobom is not published to crates.io: a release is a `vX.Y.Z` git tag, a GitHub
release with the changelog and the Linux archives (x86_64 and aarch64), and container images on
`ghcr.io/alixanneraud/nanobom`.

## Flow

1. Pull requests are merged to `main` (squash-merged: the pull request title becomes the commit).
2. The `Release-plz` workflow opens or updates a release pull request, `chore: release vX.Y.Z`,
   that bumps the workspace version, updates `Cargo.lock` and adds the version's entry to
   `CHANGELOG.md`.
3. Review it; edit the version or the changelog in the pull request if needed (the version is
   `[workspace.package].version` in `Cargo.toml`).
4. Merge it when a release is wanted. The workflow then tags `vX.Y.Z`, drafts the GitHub
   release with the changelog entry, and calls `release.yml`, which builds both architectures
   natively, attaches the archives (with build provenance), pushes the images tagged `X.Y.Z`,
   `X.Y`, `X` and `latest`, and publishes the release. It also uploads the image's SBOM to the
   maintainer's nanobom instance, as version `X.Y` of the project `nanobom-image` (with the
   repository secret `NANOBOM_TOKEN`); a failed upload does not stop the release.

Ordinary merges never release (`release_always = false`). If the build fails, the release stays
a draft: fix the cause and run `Release` again for the tag from the Actions tab.

## Versions and the changelog

Every crate inherits the workspace version, and the versions are read from the `vX.Y.Z` tags
(`git_only`). The bump comes from the Conventional Commits since the last release:

| Commit | `>= 1.0.0` | `0.x.y` |
| --- | --- | --- |
| `fix:`, `perf:`, other types | patch | patch |
| `feat:` | minor | patch |
| `feat!:`, `fix!:` or a `BREAKING CHANGE:` footer | major | minor |

CI's `Pull request title` check requires titles of that form (`feat: add SPDX uploads`,
`fix(osv): retry on timeouts`). The changelog groups commits by type (Added, Fixed, Changed, …).

release-plz attributes a commit to the crates whose files it changes, so commits touching only
files outside `crates/` (the Dockerfile, workflows, documentation) neither appear in the
changelog nor open a release pull request; they ship with the next release. To release such a
change alone, push a tag by hand (`git tag v1.2.4 && git push origin v1.2.4`) after bumping the
version: `release.yml` runs for it and creates the release with generated notes.

## Required setup

- Settings → Actions → General → Workflow permissions: "Allow GitHub Actions to create and
  approve pull requests", so the workflow can open the release pull request. Pull requests
  opened with `GITHUB_TOKEN` do not start CI; push an empty commit to the release branch, or
  close and reopen the pull request, to run it.
- Settings → General → Pull Requests: squash merging, with the pull request title as the
  default commit message.
