# Project versions

What a project version is and why is explained in
[Concepts](../explanation/concepts.md#versions); how to use them, in
[Track several versions of a product](../how-to/track-versions.md). Uploads name versions with
the [upload API](upload-api.md#versions)'s `version` and `latest` parameters.

## States

Every version of a project has two flags:

| Flag | |
| --- | --- |
| **latest** | Exactly one version of a project is the latest: the one the project page, the [read API](read-api.md#versions) and the [VEX export](vex-api.md) show when they are not asked for another, and the one a new version inherits its findings from |
| **active** | Whether runs evaluate the version. A new version is active. The latest version is always active |

An **inactive** version is kept as it was when it was made inactive:

| | Active version | Inactive version |
| --- | :---: | :---: |
| Evaluated by runs (findings opened, fixed, reopened; ignores expire) | ✓ | |
| Counted on the organization page and in the projects of the read API | ✓ | |
| Counted in the [metrics](metrics.md) (`nanobom_open_findings`, `nanobom_open_findings_known_exploited`) | ✓ | |
| Found by component searches | ✓ | With **Include inactive versions** (interface) or `inactive=true` ([read API](read-api.md#projects-components-runs-and-search)) |
| Listed in a finding's **Also affected** (`affected_components`) | ✓ | |
| Notified: `findings.new`, known exploited, emails | ✓ | |
| Shown on the project page (selector, **Versions** table) and in `/versions` | ✓ | ✓, marked inactive |
| Readable: findings, components, license violations, finding pages, VEX export | ✓ | ✓ |
| Listed in a finding's **Versions of this project** (`versions`) | ✓ | ✓, marked inactive |

Staleness stays per project: an inactive version does not make its project stale.

## Changes

| Change | How | Refused when |
| --- | --- | --- |
| Make a version inactive | **Make inactive** in the project page's **Versions** table | It is the latest: mark another version latest first |
| Make a version active again | **Make active**, or any upload to the version | Through the interface only: the project already has 50 active versions (an upload makes room instead, see [the cap](#the-cap)) |
| Mark a version latest | **Make latest**, or an upload with `latest=true`; an upload creating a version also makes it the latest unless `latest=false` | It is inactive: make it active first (an upload with `latest=true` makes it active) |
| Delete a version | **Delete**, then tick the confirmation box and select **Delete version** | It is the latest, or the project's only version: delete the project instead |

Changing versions takes the permission to delete projects: admins and owners
([roles](accounts.md)); viewers and members see the **Versions** table without its actions.
There is no API to change versions besides uploads. A version made active in the interface is
checked at once by a run of its project; otherwise the next run catches up.

Deleting a version deletes its components, dependency graph, upload history and findings with
their history, in one transaction. Other versions keep theirs, including findings they
inherited from the deleted one. Nothing else deletes a version, except deleting its project.

The error messages:

| Refusal | Message |
| --- | --- |
| Making the latest version inactive | `the latest version cannot be made inactive: mark another version latest first` |
| Marking an inactive version latest | `an inactive version cannot be the latest: make it active first` |
| Deleting the latest version | `the latest version cannot be deleted: mark another version latest first` |
| Deleting the only version | `a project keeps at least one version: delete the project instead` |
| Making a version active past the cap | `this project already has 50 active versions: make one inactive first` |

## The cap

A project has at most **50 active versions**. When an upload would create a version, or make an
inactive one active again, while the project already has 50, nanobom first makes one other
version inactive, in the upload's transaction, and the upload proceeds:

- the active version whose last upload is the oldest goes, a version never uploaded to counting
  from its creation;
- never the latest version, nor the version uploaded to;
- the server logs it (`version made inactive: the project reached its maximum of active
  versions`, with the project and the version).

Inactive versions are never deleted automatically: a project that receives a new version name
with every build keeps every build, the last 50 of them active.
