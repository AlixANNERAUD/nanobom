# Languages

The web interface is available in **English** and **French**. Each request is answered in:

1. the language chosen with the language switch in the page header, remembered in the
   `nanobom_locale` cookie of that browser (it holds only the chosen language);
2. otherwise, the best match among the browser's preferred languages (`Accept-Language`);
3. otherwise, English.

The choice is per browser, not per account: signing in elsewhere starts from the browser's
preferences again. The switch works without JavaScript, like the rest of the interface.

Error messages of the interface are translated too. Some texts stay in English whatever the
language:

- the upload API's messages, since they end up in CI logs read by whoever maintains the pipeline;
- webhook payloads and logs, which are meant for programs;
- vulnerability descriptions, which come from OSV as published;
- the label of the single sign-on button, which is set by `NANOBOM_OIDC_BUTTON_LABEL`.

Dates are shown in UTC.

Translations live in `crates/app/locales/` (interface) and `crates/domain/locales/` (messages of
the domain, such as validation errors), one JSON file per language. A message missing from a
language fails the build, so a release never shows a half-translated page. Adding a language is
described in [Develop and contribute](../how-to/develop.md#add-a-language).
