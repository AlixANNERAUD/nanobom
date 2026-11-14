# Publish a public page of a project

This guide publishes a page of a project's findings that anyone with its address can read, for
an open-source project whose README carries the nanobom [badge](badge.md). Visitors who click
the badge see what is behind the counts, and how each advisory was triaged, for example "not
affected, vulnerable code not reachable", instead of filing an issue about their own scanner's
alert.

The page is off by default, project by project. Once on, anyone with its address sees the open
and ignored findings of the latest version (or another version by name) and a VEX document of
them, never the reasons members wrote when ignoring a finding nor who triaged it.
[Public pages](../reference/public-pages.md) lists exactly what is shown.

## When not to

Leave the page off for private and commercial projects: their findings tell an attacker which
vulnerable components they ship. The address is the page's only protection, and anyone it
reaches can pass it on.

## Turn the page on

1. Open the project's page and find the **Public page** section, near the bottom. Only admins,
   owners and instance administrators see it.
2. Select **Turn on**.

The section now shows the page's address, such as
`https://nanobom.example.com/public/9b2d…41`. Open it to check what visitors will see. The
address starts with `NANOBOM_PUBLIC_URL` ([Configuration](../reference/configuration.md)): it
must be reachable from the internet, or at least its `/public/` path.

## Link it from the badge

While the public page is on, the **Markdown for a README** field of the **Badge** section links
the badge to the public page instead of the project page, which only members can open:

```markdown
[![vulnerabilities](https://nanobom.example.com/badges/3f6c…e1.svg)](https://nanobom.example.com/public/9b2d…41)
```

Paste it in place of the old snippet. The badge and the page have separate addresses: turning
the page on does not change the badge's.

## Write triage for the public

The page shows each ignored finding's VEX justification, such as **Vulnerable code not
reachable**, but never the reason typed with it. Choose a justification when ignoring a finding
([Triage findings](triage.md)): an ignore without one appears as **None (accepted risk)**.

## Point scanners at the VEX document

The page links its VEX document, at the page's address followed by `/vex.json`. Users whose
scanner reads CycloneDX VEX documents can give it this one to hide what the maintainers assessed
as not affecting the project.

## Change or revoke the address

- **New address** gives the page another address; the old one stops working at once. Update the
  badge snippet in the README.
- **Turn off** removes the page; its address stops working at once, and the badge snippet links
  to the project page again.

Pages are cached for up to five minutes by browsers and proxies, so a page turned off may still
show briefly where it was already opened. Deleting the project removes its page too.
