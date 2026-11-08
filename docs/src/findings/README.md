# Findings and prioritization

A project with a few hundred dependencies easily has dozens of findings. This chapter explains
where they come from and how nanobom helps you decide which ones matter:

- [Runs and matching](runs.md): when components are checked, how OSV results become findings,
  how aliases are merged and how severity is computed.
- [Exploitation signals](exploitation.md): CISA's Known Exploited Vulnerabilities catalog and
  FIRST's EPSS scores, and the order findings are listed in.
- [Triage, stale projects and search](triage.md): ignoring findings with a reason, spotting
  projects whose SBOM stopped coming, and finding which projects use a package.

A reasonable routine, from most to least urgent:

1. **Known exploited** findings: someone exploits them in the wild. CISA gives federal agencies a
   due date to fix each one; it is a fair deadline for anyone.
2. **Critical and high** findings with a high EPSS score.
3. The rest, by severity, during regular dependency updates.

Findings that do not apply (vulnerable code not reachable, feature not compiled in, accepted
risk) are **ignored** with a reason, ideally with an expiry date so the decision is revisited.
