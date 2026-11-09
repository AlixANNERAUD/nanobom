# Fonts

The interface bundles its fonts, so a page never asks a third party for one. The files are
copied unchanged from the [Fontsource](https://fontsource.org) npm packages below: the `latin`
subset only (Basic Latin and Latin-1, which covers English and French), as WOFF2.
`style/main.css` declares them with `@font-face`.

| File | Font | Package | Version | SHA-256 |
| --- | --- | --- | --- | --- |
| `inter-latin-wght-normal.woff2` | Inter, variable weight 100 to 900 | `@fontsource-variable/inter` | 5.3.0 | `3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62` |
| `ibm-plex-mono-latin-400-normal.woff2` | IBM Plex Mono, regular | `@fontsource/ibm-plex-mono` | 5.3.0 | `08949f728dc52d528e69b1667d15c89a5686a4ee9a296ff90983985f99c380f7` |
| `ibm-plex-mono-latin-500-normal.woff2` | IBM Plex Mono, medium | `@fontsource/ibm-plex-mono` | 5.3.0 | `01d285447409c8a588692162439a038b8cbd7871309ee20267b0d2d91c6e8e22` |

Each file comes from `https://cdn.jsdelivr.net/npm/<package>@<version>/files/<file>`, and each
licence text from `https://cdn.jsdelivr.net/npm/<package>@<version>/LICENSE`.

Both fonts are under the SIL Open Font License 1.1: `LICENSE-Inter.txt` and
`LICENSE-IBM-Plex-Mono.txt`.

To update a font, download the new file and licence, then change the version and checksum
here. The `unicode-range` in `style/main.css` is the one of the package's `latin` subset
(`wght.css` for Inter, `400.css` and `500.css` for IBM Plex Mono): check it still matches.
