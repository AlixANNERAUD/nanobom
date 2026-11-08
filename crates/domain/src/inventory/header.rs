//! The fields that tell SBOM formats apart, read from every upload before the document itself.
//!
//! The header is a first pass over a document of up to the upload size limit, so it keeps only
//! what detection needs and skips the rest with [`IgnoredAny`], which builds nothing: a
//! `serde_json::Value` or an untagged enum would buffer whatever an unknown or oversized field
//! holds. Fields of an unexpected JSON type are kept as [`Text::Other`] rather than failing the
//! pass, so that a CycloneDX or SPDX document with a wrong type is reported as such and not as
//! invalid JSON.

use std::fmt;

use serde::{
    Deserialize, Deserializer,
    de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
};

use super::capped;

/// What the header pass found. Missing and `null` fields are both `None`.
#[derive(Default)]
pub(super) struct Header {
    /// `bomFormat`, `CycloneDX` in CycloneDX documents.
    pub(super) format: Option<Text>,
    /// `specVersion`, the CycloneDX version.
    pub(super) specification_version: Option<Text>,
    /// `spdxVersion`, the SPDX 2 version.
    pub(super) spdx_version: Option<Text>,
    /// `@context`, the JSON-LD context of SPDX 3 documents, which have no `spdxVersion`.
    pub(super) context: Option<Context>,
}

/// A header field that should be a string.
pub(super) enum Text {
    /// The string, cut to the length of an error message (see [`capped`]): the values that
    /// matter are short, and a longer one is only ever echoed back.
    Text(String),
    /// Another JSON type, skipped.
    Other,
}

/// What a JSON-LD `@context` says about SPDX.
#[derive(Default)]
pub(super) struct Context {
    /// Some string of the context names the SPDX vocabulary (`spdx.org/rdf/`).
    pub(super) names_spdx: bool,
    /// The SPDX version of the first SPDX URL that has one, as SPDX 2 spells versions:
    /// `https://spdx.org/rdf/3.0.1/spdx-context.jsonld` gives `SPDX-3.0.1`. The SPDX 2 RDF
    /// vocabulary (`spdx.org/rdf/terms`) has none.
    pub(super) version: Option<String>,
}

impl Context {
    fn read(&mut self, text: &str) {
        let Some((_, rest)) = text.split_once("spdx.org/rdf/") else {
            return;
        };
        self.names_spdx = true;
        let segment = rest.split(['/', '#']).next().unwrap_or_default();
        let is_version = segment.starts_with(|character: char| character.is_ascii_digit())
            && segment.len() <= 16
            && segment
                .chars()
                .all(|character| character.is_ascii_digit() || character == '.');
        if self.version.is_none() && is_version {
            self.version = Some(format!("SPDX-{segment}"));
        }
    }
}

impl<'de> Deserialize<'de> for Header {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(HeaderVisitor)
    }
}

struct HeaderVisitor;

impl<'de> Visitor<'de> for HeaderVisitor {
    type Value = Header;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Header, A::Error> {
        let mut header = Header::default();
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::Format => header.format = map.next_value()?,
                Key::SpecificationVersion => header.specification_version = map.next_value()?,
                Key::SpdxVersion => header.spdx_version = map.next_value()?,
                Key::Context => header.context = map.next_value()?,
                Key::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(header)
    }
}

/// A key of the document's top-level object, compared without being copied.
enum Key {
    Format,
    SpecificationVersion,
    SpdxVersion,
    Context,
    Other,
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeyVisitor;
        impl Visitor<'_> for KeyVisitor {
            type Value = Key;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a key")
            }

            fn visit_str<E>(self, key: &str) -> Result<Key, E> {
                Ok(match key {
                    "bomFormat" => Key::Format,
                    "specVersion" => Key::SpecificationVersion,
                    "spdxVersion" => Key::SpdxVersion,
                    "@context" => Key::Context,
                    _ => Key::Other,
                })
            }
        }
        deserializer.deserialize_identifier(KeyVisitor)
    }
}

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TextVisitor)
    }
}

struct TextVisitor;

impl<'de> Visitor<'de> for TextVisitor {
    type Value = Text;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_str<E>(self, text: &str) -> Result<Text, E> {
        Ok(Text::Text(capped(text)))
    }

    fn visit_bool<E>(self, _: bool) -> Result<Text, E> {
        Ok(Text::Other)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Text, E> {
        Ok(Text::Other)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Text, E> {
        Ok(Text::Other)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Text, E> {
        Ok(Text::Other)
    }

    fn visit_unit<E>(self) -> Result<Text, E> {
        Ok(Text::Other)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Text, A::Error> {
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Text::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Text, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Text::Other)
    }
}

impl<'de> Deserialize<'de> for Context {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut context = Context::default();
        Scan(&mut context).deserialize(deserializer)?;
        Ok(context)
    }
}

/// Reads every string of a JSON value, keys included, into a [`Context`]. A context is a URL,
/// an array of URLs and objects, or an object mapping terms to URLs or to objects holding them;
/// whatever the shape, the SPDX URLs are strings somewhere in it. Nesting is bounded by
/// `serde_json`'s recursion limit.
struct Scan<'a>(&'a mut Context);

impl<'de> DeserializeSeed<'de> for Scan<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Scan<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_str<E>(self, text: &str) -> Result<(), E> {
        self.0.read(text);
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        while sequence.next_element_seed(Scan(&mut *self.0))?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while map.next_key_seed(Scan(&mut *self.0))?.is_some() {
            map.next_value_seed(Scan(&mut *self.0))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_values_are_skipped_without_being_kept() {
        let mut document = br#"{"bomFormat": "CycloneDX", "@context": ["#.to_vec();
        document.extend(b"0,".repeat(4 * 1024 * 1024));
        document.extend(br#"{"a": [null, true, 1.5, "x"]}], "specVersion": "1.6","#);
        document.extend(br#""spdxVersion": {"nested": [1, 2]}, "other": ["#);
        document.extend(b"[],".repeat(1024 * 1024));
        document.extend(b"[]]}");
        let header: Header = serde_json::from_slice(&document).unwrap();
        assert!(matches!(header.format, Some(Text::Text(format)) if format == "CycloneDX"));
        assert!(
            matches!(header.specification_version, Some(Text::Text(version)) if version == "1.6")
        );
        assert!(matches!(header.spdx_version, Some(Text::Other)));
        let context = header.context.unwrap();
        assert!(!context.names_spdx);
        assert_eq!(context.version, None);
    }

    #[test]
    fn contexts_give_the_spdx_version_wherever_it_is() {
        let context = |json: &str| serde_json::from_str::<Context>(json).unwrap();
        let version = |json: &str| context(json).version;
        assert_eq!(
            version(r#""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""#).as_deref(),
            Some("SPDX-3.0.1")
        );
        assert_eq!(
            version(r#"[{"@vocab": "https://example.org/"}, "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"]"#)
                .as_deref(),
            Some("SPDX-3.0.0")
        );
        // An inline context, mapping terms to the vocabulary.
        assert_eq!(
            version(
                r#"{"spdx": "https://spdx.org/rdf/3.0.1/terms/",
                    "name": {"@id": "https://spdx.org/rdf/3.0.1/terms/Core/name"}}"#
            )
            .as_deref(),
            Some("SPDX-3.0.1")
        );
        // The SPDX 2 vocabulary has no version.
        let terms = context(r#"{"spdx": "http://spdx.org/rdf/terms#"}"#);
        assert!(terms.names_spdx);
        assert_eq!(terms.version, None);
        let other = context(r#"["https://schema.org/", {"spdx": 3}]"#);
        assert!(!other.names_spdx);
    }

    #[test]
    fn long_texts_are_cut() {
        let long = format!(r#""{}""#, "é".repeat(1000));
        let Text::Text(text) = serde_json::from_str(&long).unwrap() else {
            panic!("a string");
        };
        assert_eq!(text.chars().count(), 201);
        assert!(text.ends_with('\u{2026}'));
    }
}
