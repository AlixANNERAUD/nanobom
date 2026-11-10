//! Advisory text as HTML, for the finding page.
//!
//! Advisories are Markdown written by strangers and [`render`]'s result is inserted into the
//! page as it is (`inner_html`), so everything rests on one invariant: **no markup of the result
//! comes from the source**. The parser's events are rewritten before they reach
//! pulldown-cmark's HTML writer:
//!
//! - HTML of the source becomes text, which the writer escapes: it is shown, never interpreted.
//! - Elements are rebuilt from fixed names, without what the source can attach to them (heading
//!   attributes, the language of a code block, column alignment, link and image titles). The
//!   only attributes of the result are `href` and `rel` on links, and `start` (a number) on
//!   ordered lists.
//! - A link keeps its target only when [`link_target`] accepts it, and is written here, escaped.
//!   Any other link is reduced to its text.
//! - An image becomes a link to its address: showing it would make every reader's browser
//!   request an address chosen by the advisory's author.
//! - Events of extensions that are not enabled are dropped or shown as text, so enabling one
//!   later cannot let its markup through unnoticed.
//!
//! The matches below name every event and element on purpose, without a catch-all arm: a
//! pulldown-cmark release that adds one stops compiling here until someone decides what it may
//! write.
//!
//! The text is also untrusted in size. A page is rendered on every load, so [`render`] bounds
//! what a text can cost: its length, the cells of its tables, and how much it grows once
//! rendered (the `MAX_*` constants below). Past a bound, the text is shown as it was written,
//! which costs what it weighs.

use pulldown_cmark::{
    CodeBlockKind, Event, HeadingLevel, LinkType, Options, Parser, Tag, TagEnd, html,
};

use crate::model::link_target;

/// Advisory links are followed from a page that names the reader's projects: the target learns
/// neither the page (`noreferrer`) nor gets a handle on it (`noopener`), and search engines do
/// not count the link (`nofollow`).
const REL: &str = "noopener noreferrer nofollow";

/// The longest text read as Markdown, in bytes. Real advisories are a few kilobytes; the
/// parser builds its whole tree before the first event, so the bound is on the source.
const MAX_SOURCE: usize = 256 * 1024;

/// The most table cells a text may hold for tables to be read. The parser fills short rows with
/// empty cells up to the width of the header, so a few kilobytes (a header of hundreds of
/// columns, then rows of one letter) would otherwise become megabytes of cells, in memory and
/// in the page. Beyond the bound, tables are shown as the text they are.
const MAX_TABLE_CELLS: usize = 20_000;

/// How many times its source the result may weigh. Formatted text weighs two or three times its
/// Markdown, a table of short cells five, a list of bare addresses seven; more than this is a
/// text built to be expensive (levels of quotes nested by the thousand, one definition
/// referenced by thousands of short links).
const MAX_GROWTH: usize = 16;

/// What a result may weigh on top of [`MAX_GROWTH`] times its source, in bytes.
const GROWTH_ALLOWANCE: usize = 4096;

/// Renders untrusted Markdown to HTML that is safe to insert into a page (see the module
/// documentation). Headings are demoted by two levels, to nest under the title of the card that
/// holds the text.
///
/// A text that is too long, grows too much once rendered, or makes the parser panic is shown
/// as plain text instead: the page of its finding stays readable either way.
pub fn render(source: &str) -> String {
    if source.len() > MAX_SOURCE {
        return plain(source);
    }
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    if table_cells_bound(source) <= MAX_TABLE_CELLS {
        options.insert(Options::ENABLE_TABLES);
    }
    let rendered = std::panic::catch_unwind(|| {
        let mut rewriter = Rewriter::default();
        let events = Parser::new_ext(source, options).filter_map(|event| rewriter.rewrite(event));
        let mut output = String::with_capacity(source.len() + source.len() / 4);
        html::push_html(&mut output, events);
        output
    });
    match rendered {
        // The allowance on top lets a short text be all markup (`# a`, a rule, a small table).
        Ok(output) if output.len() <= source.len() * MAX_GROWTH + GROWTH_ALLOWANCE => output,
        _ => plain(source),
    }
}

/// An upper bound on the cells of the tables of a text, padding included. A table cannot hold a
/// blank line, and none of its rows has more cells than the line with the most `|` has, plus
/// one. So no table of a run of lines holds more than its lines times that width; runs without
/// a `|` hold no table.
fn table_cells_bound(source: &str) -> usize {
    let mut total = 0_usize;
    let mut lines = 0_usize;
    let mut width = 0_usize;
    for line in source.lines().chain([""]) {
        if line.trim().is_empty() {
            if width > 0 {
                total = total.saturating_add(lines.saturating_mul(width + 1));
            }
            lines = 0;
            width = 0;
        } else {
            lines += 1;
            width = width.max(line.bytes().filter(|byte| *byte == b'|').count());
        }
    }
    total
}

/// A text as it was written: escaped, one paragraph, its line breaks kept.
fn plain(source: &str) -> String {
    let mut output = String::with_capacity(source.len() + source.len() / 8);
    output.push_str("<p>");
    for (index, line) in source.lines().enumerate() {
        if index > 0 {
            output.push_str("<br />\n");
        }
        output.push_str(&escape(line));
    }
    output.push_str("</p>\n");
    output
}

/// The link being written.
struct Anchor {
    /// Its target, escaped.
    target: String,
    /// Links and images opened inside it and not closed yet: their ends are not its own.
    nested: usize,
    /// Whether nothing visible was written inside it so far.
    empty: bool,
}

/// Rewrites the parser's events into the ones the HTML writer may see.
///
/// The writer copies [`Event::Html`] and [`Event::InlineHtml`] to the result as they are. After
/// the rewrite, the only such events are the opening and closing tags of links, built in
/// [`Rewriter::open`] and [`Rewriter::close`].
#[derive(Default)]
struct Rewriter {
    anchor: Option<Anchor>,
}

impl Rewriter {
    fn rewrite<'a>(&mut self, event: Event<'a>) -> Option<Event<'a>> {
        match event {
            Event::Start(tag) => self.start(tag),
            Event::End(end) => self.end(end),
            // Math and footnotes are extensions that stay off; should one be enabled, its
            // source is shown as it was written.
            Event::Text(text)
            | Event::Html(text)
            | Event::InlineHtml(text)
            | Event::InlineMath(text)
            | Event::DisplayMath(text)
            | Event::FootnoteReference(text) => {
                self.written(&text);
                Some(Event::Text(text))
            }
            Event::Code(code) => {
                self.written(&code);
                Some(Event::Code(code))
            }
            Event::SoftBreak => Some(Event::SoftBreak),
            Event::HardBreak => Some(Event::HardBreak),
            Event::Rule => Some(Event::Rule),
            // Would be written as an `<input>`.
            Event::TaskListMarker(_) => None,
        }
    }

    fn start<'a>(&mut self, tag: Tag<'a>) -> Option<Event<'a>> {
        let tag = match tag {
            Tag::Paragraph => Tag::Paragraph,
            Tag::Heading { level, .. } => Tag::Heading {
                level: demote(level),
                id: None,
                classes: Vec::new(),
                attrs: Vec::new(),
            },
            Tag::BlockQuote(_) => Tag::BlockQuote(None),
            // An indented block is written without the `class` a fenced one gets from its
            // language.
            Tag::CodeBlock(_) => Tag::CodeBlock(CodeBlockKind::Indented),
            // The lines of the block follow as `Event::Html`, which `rewrite` turns into text.
            Tag::HtmlBlock => Tag::Paragraph,
            Tag::List(first) => Tag::List(first),
            Tag::Item => Tag::Item,
            // Without alignments: the writer sets them with a `style` attribute.
            Tag::Table(_) => Tag::Table(Vec::new()),
            Tag::TableHead => Tag::TableHead,
            Tag::TableRow => Tag::TableRow,
            Tag::TableCell => Tag::TableCell,
            Tag::Emphasis => Tag::Emphasis,
            Tag::Strong => Tag::Strong,
            Tag::Strikethrough => Tag::Strikethrough,
            Tag::Link {
                link_type: LinkType::Email,
                dest_url,
                ..
            } => return self.open(&format!("mailto:{dest_url}")),
            Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. } => {
                return self.open(&dest_url);
            }
            // Extensions that stay off. Their text, if any, is kept.
            Tag::FootnoteDefinition(_)
            | Tag::DefinitionList
            | Tag::DefinitionListTitle
            | Tag::DefinitionListDefinition
            | Tag::Superscript
            | Tag::Subscript
            | Tag::MetadataBlock(_) => return None,
        };
        Some(Event::Start(tag))
    }

    fn end<'a>(&mut self, end: TagEnd) -> Option<Event<'a>> {
        let end = match end {
            TagEnd::Paragraph | TagEnd::HtmlBlock => TagEnd::Paragraph,
            TagEnd::Heading(level) => TagEnd::Heading(demote(level)),
            TagEnd::BlockQuote(_) => TagEnd::BlockQuote(None),
            TagEnd::CodeBlock => TagEnd::CodeBlock,
            TagEnd::List(ordered) => TagEnd::List(ordered),
            TagEnd::Item => TagEnd::Item,
            TagEnd::Table => TagEnd::Table,
            TagEnd::TableHead => TagEnd::TableHead,
            TagEnd::TableRow => TagEnd::TableRow,
            TagEnd::TableCell => TagEnd::TableCell,
            TagEnd::Emphasis => TagEnd::Emphasis,
            TagEnd::Strong => TagEnd::Strong,
            TagEnd::Strikethrough => TagEnd::Strikethrough,
            TagEnd::Link | TagEnd::Image => return self.close(),
            TagEnd::FootnoteDefinition
            | TagEnd::DefinitionList
            | TagEnd::DefinitionListTitle
            | TagEnd::DefinitionListDefinition
            | TagEnd::Superscript
            | TagEnd::Subscript
            | TagEnd::MetadataBlock(_) => return None,
        };
        Some(Event::End(end))
    }

    /// Starts a link or an image, both written as a link to `address`. Nothing is written when
    /// the address is not an allowed target, or inside another link (HTML has no nested links):
    /// what the link or image holds then reads as plain text.
    fn open<'a>(&mut self, address: &str) -> Option<Event<'a>> {
        if let Some(anchor) = &mut self.anchor {
            anchor.nested += 1;
            return None;
        }
        let target = escape(link_target(address)?);
        let tag = format!("<a href=\"{target}\" rel=\"{REL}\">");
        self.anchor = Some(Anchor {
            target,
            nested: 0,
            empty: true,
        });
        Some(Event::Html(tag.into()))
    }

    /// Ends a link or an image. Events are balanced, so an end that is not the one of the link
    /// being written belongs to a link or image for which [`Rewriter::open`] wrote nothing.
    fn close<'a>(&mut self) -> Option<Event<'a>> {
        let anchor = self.anchor.as_mut()?;
        if anchor.nested > 0 {
            anchor.nested -= 1;
            return None;
        }
        let anchor = self.anchor.take()?;
        // A link without text (an image without alternative text) would be invisible: it shows
        // where it leads.
        let text = if anchor.empty {
            anchor.target.as_str()
        } else {
            ""
        };
        Some(Event::Html(format!("{text}</a>").into()))
    }

    fn written(&mut self, text: &str) {
        if let Some(anchor) = &mut self.anchor
            && !text.trim().is_empty()
        {
            anchor.empty = false;
        }
    }
}

fn demote(level: HeadingLevel) -> HeadingLevel {
    match level {
        HeadingLevel::H1 => HeadingLevel::H3,
        HeadingLevel::H2 => HeadingLevel::H4,
        HeadingLevel::H3 => HeadingLevel::H5,
        HeadingLevel::H4 | HeadingLevel::H5 | HeadingLevel::H6 => HeadingLevel::H6,
    }
}

/// Escapes text for a double-quoted attribute value; the result is also valid element content.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::{GROWTH_ALLOWANCE, MAX_GROWTH, MAX_SOURCE, plain, render, table_cells_bound};
    use crate::model::link_target;

    /// Elements [`render`] may write. None takes an attribute, except `a` and `ol`.
    const ELEMENTS: [&str; 22] = [
        "p",
        "h3",
        "h4",
        "h5",
        "h6",
        "blockquote",
        "pre",
        "code",
        "ul",
        "ol",
        "li",
        "table",
        "thead",
        "tbody",
        "tr",
        "th",
        "td",
        "em",
        "strong",
        "del",
        "a",
        "hr",
    ];

    fn unescape(text: &str) -> String {
        text.replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
    }

    /// Checks the invariant of the module on a result: every `<` opens one of the elements
    /// [`render`] writes, in the exact form it writes it, and every link target is allowed.
    /// Returns the result for further assertions.
    fn harmless(source: &str) -> String {
        let html = render(source);
        assert!(
            html.len() <= source.len() * MAX_GROWTH + GROWTH_ALLOWANCE,
            "{} bytes rendered from {} bytes",
            html.len(),
            source.len()
        );
        let mut links = 0_i64;
        for (position, _) in html.match_indices('<') {
            let rest = &html[position + 1..];
            let end = rest
                .find('>')
                .unwrap_or_else(|| panic!("unclosed tag in {html:?}"));
            let tag = &rest[..end];
            assert!(!tag.contains('<'), "nested `<` in {html:?}");
            let allowed = if let Some(name) = tag.strip_prefix('/') {
                links -= i64::from(name == "a");
                ELEMENTS.contains(&name) && name != "hr"
            } else if let Some(attributes) = tag.strip_prefix("a ") {
                links += 1;
                attributes
                    .strip_prefix("href=\"")
                    .and_then(|rest| rest.strip_suffix("\" rel=\"noopener noreferrer nofollow\""))
                    .is_some_and(|target| {
                        !target.contains('"') && link_target(&unescape(target)).is_some()
                    })
            } else if let Some(start) = tag.strip_prefix("ol start=\"") {
                start.strip_suffix('"').is_some_and(|number| {
                    !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
                })
            } else {
                tag == "hr /"
                    || tag == "br /"
                    || (ELEMENTS.contains(&tag) && tag != "a" && tag != "hr")
            };
            assert!(allowed, "`<{tag}>` in {html:?} (from {source:?})");
            assert!(
                (0..=1).contains(&links),
                "links are nested or closed twice in {html:?}"
            );
        }
        assert_eq!(links, 0, "a link is left open in {html:?}");
        html
    }

    #[test]
    fn html_of_the_source_is_shown_as_text() {
        let html = harmless("<script>alert(1)</script>");
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "{html}"
        );
        assert!(!html.contains("<script"));

        let html = harmless("a <b onmouseover=x>b</b>");
        assert!(
            html.contains("&lt;b onmouseover=x&gt;b&lt;/b&gt;"),
            "{html}"
        );
        assert!(!html.contains("<b "));

        for source in [
            "<img src=x onerror=alert(1)>",
            "text <img src=x onerror=alert(1)> text",
            "<svg/onload=alert(1)>",
            "<svg><script>alert(1)</script></svg>",
            "<iframe src=\"javascript:alert(1)\"></iframe>",
            "<a href=\"javascript:alert(1)\">x</a>",
            "<a href=\"https://example.org\" onclick=\"alert(1)\">x</a>",
            "<form action=\"https://example.org\"><input name=password></form>",
            "<style>body{display:none}</style>",
            "<base href=\"https://example.org/\">",
            "<meta http-equiv=\"refresh\" content=\"0;url=https://example.org\">",
            "<link rel=stylesheet href=\"https://example.org/x.css\">",
            "<object data=\"https://example.org/x\"></object>",
            "<details open ontoggle=alert(1)>x</details>",
            "<p style=\"position:fixed;inset:0\">x</p>",
            "<div>\n\n<script>alert(1)</script>\n\n</div>",
            "<SCRIPT>alert(1)</SCRIPT>",
            "<script\n>alert(1)</script\n>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<<script>script>alert(1)<</script>/script>",
            "<b <i onmouseover=alert(1)>x",
            "<script",
            "<script>alert(1)",
            "<div title=\"",
            "<div title=\"><script>alert(1)</script>",
            "</p><script>alert(1)</script>",
            "</a></div><script>alert(1)</script>",
            "<!-- comment --><script>alert(1)</script>",
            "<!-- <script>alert(1)</script> -->",
            "<!--><script>alert(1)</script>-->",
            "<!--\n<script>alert(1)</script>\n-->\n\ntext",
            "<![CDATA[<script>alert(1)</script>]]>",
            "text <![CDATA[<script>alert(1)</script>]]> text",
            "<?php echo 1; ?><script>alert(1)</script>",
            "<!DOCTYPE html><script>alert(1)</script>",
            "\u{0}<script>alert(1)</script>",
            "<\u{0}script>alert(1)</script>",
        ] {
            let html = harmless(source);
            assert!(!html.to_lowercase().contains("<script"), "{html}");
        }
    }

    #[test]
    fn html_stays_text_inside_every_construct() {
        let hostile = "<img src=x onerror=alert(1)>";
        for source in [
            format!("# {hostile}"),
            format!("- {hostile}\n- b"),
            format!("1. {hostile}"),
            format!("> {hostile}"),
            format!("*{hostile}*"),
            format!("**{hostile}**"),
            format!("~~{hostile}~~"),
            format!("`{hostile}`"),
            format!("```\n{hostile}\n```"),
            format!("    {hostile}"),
            format!("[{hostile}](https://example.org)"),
            format!("![{hostile}](https://example.org/l.png)"),
            format!("| a |\n| --- |\n| {hostile} |"),
            format!("| {hostile} |\n| --- |\n| b |"),
            format!("- > 1. {hostile}"),
        ] {
            let html = harmless(&source);
            assert!(
                html.contains("&lt;img src=x onerror=alert(1)&gt;"),
                "{html}"
            );
        }
    }

    #[test]
    fn escaped_markup_of_the_source_stays_escaped() {
        for source in [
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            "\\<script\\>alert(1)\\</script\\>",
        ] {
            let html = harmless(source);
            assert!(
                html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
                "{html}"
            );
        }
        assert_eq!(
            harmless("a & b &amp; c &copy; \"d\""),
            "<p>a &amp; b &amp; c © \"d\"</p>\n"
        );
    }

    #[test]
    fn links_keep_web_and_mail_targets_only() {
        for source in [
            "[x](javascript:alert(1))",
            "[x](JaVaScRiPt:alert(1))",
            "[x](&#106;avascript:alert(1))",
            "[x](&#x6A;avascript:alert(1))",
            "[x](javascript&colon;alert(1))",
            "[x](java&Tab;script:alert(1))",
            "[x](java&NewLine;script:alert(1))",
            "[x]( javascript:alert(1))",
            "[x](<javascript:alert(1)>)",
            "[x](< javascript:alert(1)>)",
            "[x](<java\tscript:alert(1)>)",
            "[x](\u{1}javascript:alert(1))",
            "[x](&#1;javascript:alert(1))",
            "[x](\u{a0}javascript:alert(1))",
            "[x](javascript:alert(1) \"title\")",
            "[x](javascript://example.org/%0Aalert(1))",
            "[x](javascript:alert(1)//https://example.org)",
            "[x](javascript&#58;alert(1))",
            "[x](&#0000106;avascript:alert(1))",
            "[x](&#X6A;avascript:alert(1))",
            "[x](%6Aavascript:alert(1))",
            "[x](\njavascript:alert(1))",
            "[x](\u{2028}javascript:alert(1))",
            "[x](\u{feff}javascript:alert(1))",
            "[x](<\u{0}javascript:alert(1)>)",
            "[x](<javascript:alert(1)\u{0}>)",
            "[x](jav&#x09;ascript:alert(1))",
            "[x](jav&#x0A;ascript:alert(1))",
            "[x](jav&#x0D;ascript:alert(1))",
            "[x](data:text/html,hi)",
            "[x](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)",
            "[x](DATA:text/html,hi)",
            "[x](vbscript:x)",
            "[x](VBScript:x)",
            "[x](file:///etc/passwd)",
            "[x](ftp://example.org/x)",
            "[x](blob:https://example.org/1)",
            "[x](view-source:https://example.org)",
            "[x](//example.org/x)",
            "[x](/organizations)",
            "[x](../settings)",
            "[x](relative.md)",
            "[x](#fragment)",
            "[x](?query=1)",
            "[x]()",
            "[x](https:example.org)",
            "[x](https:/example.org)",
            "[x](http:\\\\example.org)",
            "[x](ht\u{200b}tps://example.org)",
            "[x](<ht\ttps://example.org>)",
            "[x](<https://example.org/\u{1}>)",
            "[x][r]\n\n[r]: javascript:alert(1)",
            "[x][r]\n\n[r]: <javascript:alert(1)> \"title\"",
            "[x][]\n\n[x]: javascript:alert(1)",
            "[x]\n\n[x]: javascript:alert(1)",
            "[x]\n\n[X]: JAVASCRIPT:alert(1)",
            "[x][r]\n\n[r]: data:text/html,hi",
            "[x][r]\n\n[r]: &#106;avascript:alert(1)",
        ] {
            let html = harmless(source);
            assert!(html.contains('x'), "{source}: {html}");
            assert!(!html.contains("href"), "{source}: {html}");
            assert!(!html.contains("<a"), "{source}: {html}");
        }

        assert_eq!(
            harmless("[x](https://example.org/a?b=1&c=2)"),
            "<p><a href=\"https://example.org/a?b=1&amp;c=2\" rel=\"noopener noreferrer nofollow\">x</a></p>\n"
        );
        for (source, target) in [
            ("[x](http://example.org)", "http://example.org"),
            ("[x](HTTPS://EXAMPLE.ORG/A)", "HTTPS://EXAMPLE.ORG/A"),
            ("[x]( https://example.org )", "https://example.org"),
            ("[x](<https://example.org/a b>)", "https://example.org/a b"),
            (
                "[x](mailto:security@example.org)",
                "mailto:security@example.org",
            ),
            (
                "[x](https://example.org \"a title\")",
                "https://example.org",
            ),
            ("[x][r]\n\n[r]: https://example.org", "https://example.org"),
            (
                "[x]\n\n[x]: https://example.org 'a title'",
                "https://example.org",
            ),
        ] {
            let html = harmless(source);
            assert!(
                html.contains(&format!(
                    "<a href=\"{target}\" rel=\"noopener noreferrer nofollow\">x</a>"
                )),
                "{source}: {html}"
            );
            assert!(!html.contains("title"), "{source}: {html}");
        }
    }

    #[test]
    fn autolinks_follow_the_same_rule() {
        for source in [
            "<javascript:alert(1)>",
            "<JAVASCRIPT:alert(1)>",
            "<data:text/html,hi>",
            "<vbscript:x>",
            "<file:///etc/passwd>",
            "<x-custom:payload>",
        ] {
            let html = harmless(source);
            assert!(!html.contains("href"), "{source}: {html}");
            // The address is still shown.
            assert!(
                html.contains(&source[1..source.len() - 1]),
                "{source}: {html}"
            );
        }
        assert_eq!(
            harmless("<https://example.org/a?b=1&c=2>"),
            "<p><a href=\"https://example.org/a?b=1&amp;c=2\" rel=\"noopener noreferrer nofollow\">\
             https://example.org/a?b=1&amp;c=2</a></p>\n"
        );
        assert_eq!(
            harmless("<security@example.org>"),
            "<p><a href=\"mailto:security@example.org\" rel=\"noopener noreferrer nofollow\">\
             security@example.org</a></p>\n"
        );
    }

    #[test]
    fn a_target_cannot_leave_its_attribute() {
        let link = |target: &str, text: &str| {
            format!("<p><a href=\"{target}\" rel=\"noopener noreferrer nofollow\">{text}</a></p>\n")
        };
        let quoted = "https://example.org/&quot;onmouseover=&quot;alert(1)";
        assert_eq!(
            harmless("[x](https://example.org/\"onmouseover=\"alert(1))"),
            link(quoted, "x")
        );
        assert_eq!(
            harmless("[x](https://example.org/&quot;onmouseover=&quot;alert(1))"),
            link(quoted, "x")
        );
        assert_eq!(
            harmless("[x](https://example.org/&#34;onmouseover=&#34;alert(1))"),
            link(quoted, "x")
        );
        assert_eq!(
            harmless("[x](https://example.org/'onmouseover='alert(1))"),
            link("https://example.org/&#39;onmouseover=&#39;alert(1)", "x")
        );
        assert_eq!(
            harmless("[x](<https://example.org/\" onmouseover=\"alert(1)>)"),
            link("https://example.org/&quot; onmouseover=&quot;alert(1)", "x")
        );
        let markup = "https://example.org/&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;";
        assert_eq!(
            harmless("[x](https://example.org/\"><script>alert(1)</script>)"),
            link(markup, "x")
        );
        assert_eq!(
            harmless(
                "[x](https://example.org/&#34;&#62;&#60;script&#62;alert(1)&#60;/script&#62;)"
            ),
            link(markup, "x")
        );
        // The address shown for an image without alternative text is escaped as well.
        assert_eq!(
            harmless("![](https://example.org/\"><script>alert(1)</script>)"),
            link(markup, markup)
        );
        // Titles are not written at all.
        for source in [
            "[x](https://example.org \"\\\"><script>alert(1)</script>\")",
            "[x](https://example.org '\" onmouseover=\"alert(1)')",
            "![x](https://example.org \"\\\"><script>alert(1)</script>\")",
            "[x][r]\n\n[r]: https://example.org \"\\\"><script>alert(1)</script>\"",
        ] {
            assert_eq!(
                harmless(source),
                link("https://example.org", "x"),
                "{source}"
            );
        }
        for source in [
            "![\" onerror=\"alert(1)](https://example.org/l.png)",
            "<https://example.org/\"onmouseover=\"alert(1)>",
            "[x](<https://example.org/\"><script>alert(1)</script>>)",
            "[x][r]\n\n[r]: https://example.org/\"onmouseover=\"alert(1) \"\\\"><script>\"",
        ] {
            let html = harmless(source);
            assert!(!html.contains("<script"), "{source}: {html}");
        }
    }

    #[test]
    fn images_become_links_to_their_address() {
        let html = harmless("![logo](https://example.org/l.png)");
        assert!(!html.contains("<img"));
        assert_eq!(
            html,
            "<p><a href=\"https://example.org/l.png\" rel=\"noopener noreferrer nofollow\">logo</a></p>\n"
        );
        // Without an alternative text, the address is the text of the link.
        assert_eq!(
            harmless("![](https://example.org/l.png?a=1&b=2)"),
            "<p><a href=\"https://example.org/l.png?a=1&amp;b=2\" rel=\"noopener noreferrer nofollow\">\
             https://example.org/l.png?a=1&amp;b=2</a></p>\n"
        );
        assert_eq!(
            harmless("![logo][l]\n\n[l]: https://example.org/l.png \"title\""),
            "<p><a href=\"https://example.org/l.png\" rel=\"noopener noreferrer nofollow\">logo</a></p>\n"
        );
        for source in [
            "![logo](javascript:alert(1))",
            "![logo](data:image/svg+xml,<svg onload=alert(1)>)",
            "![logo](data:image/png;base64,iVBORw0KGgo=)",
            "![logo](/favicon.svg)",
            "![logo](//example.org/l.png)",
            "![logo][l]\n\n[l]: javascript:alert(1)",
        ] {
            let html = harmless(source);
            assert!(html.contains("logo"), "{source}: {html}");
            assert!(!html.contains("href"), "{source}: {html}");
            assert!(!html.contains("<img"), "{source}: {html}");
        }
        assert_eq!(harmless("![](javascript:alert(1))"), "<p></p>\n");
    }

    #[test]
    fn a_link_holds_no_other_link() {
        // A badge: the image is inside a link, and a link cannot hold another one.
        assert_eq!(
            harmless("[![build](https://example.org/badge.svg)](https://example.org/ci)"),
            "<p><a href=\"https://example.org/ci\" rel=\"noopener noreferrer nofollow\">build</a></p>\n"
        );
        // Without any text, the link shows where it leads.
        assert_eq!(
            harmless("[![](https://example.org/badge.svg)](https://example.org/ci)"),
            "<p><a href=\"https://example.org/ci\" rel=\"noopener noreferrer nofollow\">https://example.org/ci</a></p>\n"
        );
        assert_eq!(
            harmless("[](https://example.org/ci)"),
            "<p><a href=\"https://example.org/ci\" rel=\"noopener noreferrer nofollow\">https://example.org/ci</a></p>\n"
        );
        // The image of a link without a usable target still links to its own address.
        assert_eq!(
            harmless("[![build](https://example.org/badge.svg)](javascript:alert(1))"),
            "<p><a href=\"https://example.org/badge.svg\" rel=\"noopener noreferrer nofollow\">build</a></p>\n"
        );
        assert_eq!(
            harmless(
                "![a [b](https://example.org/b) c ![d](https://example.org/d)](https://example.org/a) e"
            ),
            "<p><a href=\"https://example.org/a\" rel=\"noopener noreferrer nofollow\">a b c d</a> e</p>\n"
        );
        harmless("[![a](javascript:alert(1))](javascript:alert(2))");
        harmless("![![![a](https://example.org/1)](javascript:alert(1))](https://example.org/3)");
    }

    #[test]
    fn headings_nest_under_the_card_title() {
        assert_eq!(
            harmless("# A\n### B\n###### C"),
            "<h3>A</h3>\n<h5>B</h5>\n<h6>C</h6>\n"
        );
        assert_eq!(
            harmless("## A\n#### B\n##### C"),
            "<h4>A</h4>\n<h6>B</h6>\n<h6>C</h6>\n"
        );
        assert_eq!(harmless("A\n=\n\nB\n-"), "<h3>A</h3>\n<h4>B</h4>\n");
        // Heading attributes are an extension that stays off: they are text.
        let html = harmless("# A {#id .class onclick=alert(1)}");
        assert!(html.starts_with("<h3>A {#id"), "{html}");
    }

    #[test]
    fn ordinary_formatting_renders() {
        assert_eq!(
            harmless("- a\n- b"),
            "<ul>\n<li>a</li>\n<li>b</li>\n</ul>\n"
        );
        assert_eq!(
            harmless("1. a\n2. b"),
            "<ol>\n<li>a</li>\n<li>b</li>\n</ol>\n"
        );
        assert_eq!(
            harmless("3. a\n4. b"),
            "<ol start=\"3\">\n<li>a</li>\n<li>b</li>\n</ol>\n"
        );
        assert_eq!(
            harmless("*a* **b** ~~c~~ `d<e>`"),
            "<p><em>a</em> <strong>b</strong> <del>c</del> <code>d&lt;e&gt;</code></p>\n"
        );
        assert_eq!(harmless("> a"), "<blockquote>\n<p>a</p>\n</blockquote>\n");
        assert_eq!(harmless("a  \nb\n\n---"), "<p>a<br />\nb</p>\n<hr />\n");
        assert_eq!(
            harmless("    let a = 1 < 2;\n"),
            "<pre><code>let a = 1 &lt; 2;\n</code></pre>\n"
        );
        // The language of a fenced block is dropped with whatever else follows the fence.
        for fence in [
            "```",
            "```rust",
            "```\"><script>alert(1)</script>",
            "~~~ rust onclick=alert(1)",
        ] {
            let close = &fence[..3];
            assert_eq!(
                harmless(&format!("{fence}\nlet a = \"<b>\";\n{close}")),
                "<pre><code>let a = \"&lt;b&gt;\";\n</code></pre>\n"
            );
        }
        // Column alignment would be a `style` attribute: columns are not aligned.
        assert_eq!(
            harmless("| a | b |\n| :-- | --: |\n| 1 | 2 |"),
            "<table><thead><tr><th>a</th><th>b</th></tr></thead><tbody>\n<tr><td>1</td><td>2</td></tr>\n</tbody></table>\n"
        );
    }

    #[test]
    fn extensions_that_are_off_write_nothing_of_their_own() {
        for source in [
            "- [ ] a\n- [x] b",
            "a[^1]\n\n[^1]: note <script>alert(1)</script>",
            "$x < y$ and $$x > y$$",
            "---\ntitle: <script>alert(1)</script>\n---\n\ntext",
            "term\n: definition",
            "> [!NOTE]\n> text",
            "H~2~O and x^2^",
            "[[wiki]] and [[javascript:alert(1)|x]]",
            "{{< shortcode >}}",
        ] {
            harmless(source);
        }
    }

    #[test]
    fn large_and_degenerate_texts_render() {
        let html = harmless(&"<".repeat(200 * 1024));
        assert_eq!(html.matches("&lt;").count(), 200 * 1024);

        for unit in [
            ">",
            "> ",
            "- ",
            "1. ",
            "[",
            "![",
            "[x](",
            "](",
            "*",
            "_",
            "**",
            "~~",
            "`",
            "<a",
            "<a>",
            "</a>",
            "&",
            "&#",
            "\\",
            "|",
            "| a ",
            "#",
            "\n\n",
            "\t",
            "<!--",
            "<![CDATA[",
            "<?",
            "[a]: ",
            "[x][",
            "<https://a",
            "\u{0}",
        ] {
            harmless(&unit.repeat(20_000));
        }
        assert_eq!(render(""), "");
        assert_eq!(render(" \n\t\n"), "");
    }

    /// The parser fills short rows up to the width of the header: 362 columns and 720 rows of
    /// one letter are 260,000 cells and megabytes of HTML from 3 KB of text.
    #[test]
    fn padded_tables_do_not_multiply_the_text() {
        let columns = 362;
        let table = format!(
            "{}\n{}\n{}\n",
            vec!["a"; columns].join("|"),
            vec!["-"; columns].join("|"),
            "a\n".repeat(720)
        );
        assert!(table.len() < 3 * 1024);
        for source in [table.clone(), format!("{table}\n").repeat(20)] {
            let html = harmless(&source);
            assert!(!html.contains("<td>"), "tables are not read");
            assert!(html.len() < source.len() * 4, "{} bytes", html.len());
        }
        // An ordinary table next to it is lost with it, and stays readable as text.
        let html = harmless(&format!("{table}\n| a | b |\n| - | - |\n| 1 | 2 |\n"));
        assert!(html.contains("| 1 | 2 |"), "{html}");

        // Rows as wide as the header are not padded: a real table is read whatever its size.
        let row = "| value | value | value | value |\n";
        let wide = format!("{row}| - | - | - | - |\n{}", row.repeat(500));
        assert_eq!(harmless(&wide).matches("<td>").count(), 2000);
    }

    #[test]
    fn the_bound_on_table_cells_counts_runs_of_lines_holding_a_bar() {
        assert_eq!(table_cells_bound(""), 0);
        assert_eq!(table_cells_bound("no table\nhere\n\nnor here"), 0);
        // Two columns need one bar at least: three lines of two cells.
        assert_eq!(table_cells_bound("a|b\n-|-\n1|2"), 6);
        // The widest line sets the width of its run, and a blank line ends the run.
        assert_eq!(table_cells_bound("a|b|c\n-|-|-\nx\n\ny\n\n| z |\n"), 9 + 3);
        assert_eq!(table_cells_bound("> a|b\n> -|-\n \t\nc"), 4);
    }

    #[test]
    fn a_text_past_the_bounds_is_shown_as_written() {
        assert_eq!(
            plain("# <b>title</b>\n\n[x](javascript:alert(1)) & \"quotes\"\r\nend"),
            "<p># &lt;b&gt;title&lt;/b&gt;<br />\n<br />\n[x](javascript:alert(1)) &amp; \
             &quot;quotes&quot;<br />\nend</p>\n"
        );
        // Too long to be read as Markdown.
        let long = format!("# title\n\n{}", "word ".repeat(MAX_SOURCE / 5 + 1));
        let html = harmless(&long);
        assert!(html.starts_with("<p># title<br />"), "{}", &html[..40]);
        // Built to grow: each `>` opens a quote in the one before.
        let html = harmless(&">".repeat(5000));
        assert!(!html.contains("<blockquote>"));
        // One definition, thousands of links to it.
        let html = harmless(&format!(
            "[a]: https://example.org\n\n{}",
            "[a] ".repeat(5000)
        ));
        assert!(!html.contains("<a "));
    }

    #[test]
    fn html_stays_text_in_blocks_the_parser_reads_differently() {
        for source in [
            // Line endings other than a line feed.
            "<script>\r\nalert(1)\r\n</script>",
            "<script>\ralert(1)\r</script>",
            // HTML blocks inside containers.
            "- <script>\n\n  alert(1)\n\n  </script>",
            "> <div>\n> <img src=x onerror=alert(1)>",
            "1. <iframe src=https://example.org></iframe>\n   text",
            // A reference label holding HTML.
            "[<img src=x>]: https://example.org\n\n[<img src=x>]",
            // Autolinks inside the text of a link.
            "[a <https://example.org/1> b](https://example.org/2)",
            "[<b@example.org>](https://example.org)",
        ] {
            let html = harmless(source).to_lowercase();
            for tag in ["<script", "<img", "<div", "<iframe"] {
                assert!(!html.contains(tag), "{html}");
            }
        }
    }

    /// Lists of hostile inputs cover what their author thought of. This feeds the renderer
    /// thousands of texts assembled from the pieces attacks are made of, in an order no one
    /// chose, and checks the invariant on each. The sequence is fixed, so a failure names a
    /// text that fails again.
    #[test]
    fn texts_assembled_at_random_are_harmless() {
        const PIECES: [&str; 40] = [
            "<",
            ">",
            "\"",
            "'",
            "&",
            "[",
            "]",
            "(",
            ")",
            "!",
            "|",
            "`",
            "*",
            "_",
            "~",
            "#",
            "-",
            "=",
            ":",
            "/",
            "\\",
            " ",
            "\n",
            "\n\n",
            "\t",
            "\r\n",
            "a",
            "1.",
            "x]: ",
            "javascript:",
            "https://example.org",
            "mailto:a@b.example",
            "data:text/html,",
            "<script>",
            "</script>",
            "<img src=x onerror=alert(1)>",
            "<!--",
            "]]>",
            "&#x3c;",
            "onclick=alert(1)",
        ];
        // A linear congruential generator: reproducible, and no dependency.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = |bound: usize| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(state >> 33).unwrap() % bound
        };
        for _ in 0..4000 {
            let mut source = String::new();
            for _ in 0..1 + next(40) {
                source.push_str(PIECES[next(PIECES.len())]);
            }
            harmless(&source);
        }
    }
}
