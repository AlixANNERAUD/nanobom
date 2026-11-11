# Show a badge in a README

This guide puts a badge with a project's open findings in its README, like a coverage badge: a
small image reading, for example, "vulnerabilities | 1 critical, 2 high".

nanobom data is private, so a badge is off until an admin or owner of the organization turns it
on. Once on, anyone with the badge's address sees the open findings of the project's latest
version, and nothing else ([Badges](../reference/badges.md) lists what it shows).

## Turn the badge on

1. Open the project's page and find the **Badge** section, near the bottom. Only admins and
   owners see it.
2. Select **Turn on**.

The section now shows the badge and the Markdown to paste.

## Paste the snippet

Copy the **Markdown for a README** field into the README:

```markdown
[![vulnerabilities](https://nanobom.example.com/badges/3f6c…e1.svg)](https://nanobom.example.com/organizations/acme/projects/web)
```

The image links to the project page, which only members can open. The addresses start with
`NANOBOM_PUBLIC_URL` ([Configuration](../reference/configuration.md)): for a public README, that
address must be reachable from the internet, or at least the `/badges/` path of it.

To show another version than the latest, add `?version=` and the version's name to the image
address:

```markdown
![vulnerabilities](https://nanobom.example.com/badges/3f6c…e1.svg?version=2.4)
```

The badge follows triage: an ignored finding no longer counts. Image proxies such as GitHub's
may keep a badge for up to five minutes.

## Restyle it with shields.io

The same address with `.json` instead of `.svg` answers in the
[shields.io endpoint format](https://shields.io/badges/endpoint-badge). Give it to shields.io to
change the style, the label or add a logo:

```markdown
![vulnerabilities](https://img.shields.io/endpoint?url=https%3A%2F%2Fnanobom.example.com%2Fbadges%2F3f6c…e1.json&style=for-the-badge)
```

shields.io then fetches the counts from nanobom, so the nanobom address must be reachable from
the internet.

## Change or revoke the address

The address is the badge's only protection. If it leaks where it should not, or the README goes
private:

- **New address** gives the badge another address; the old one stops working at once. Paste the
  new snippet where the old one was.
- **Turn off** removes the badge; its address stops working at once.

Deleting the project removes its badge too.
