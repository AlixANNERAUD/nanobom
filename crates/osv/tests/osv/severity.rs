//! Severity from CVSS vectors, with the fallbacks used when a record has none.

use nanobom_osv::{Severity, Vulnerability, assess};
use serde_json::json;

fn record(extra: serde_json::Value) -> Vulnerability {
    let mut value = json!({"id": "TEST-1", "modified": "2024-01-01T00:00:00Z"});
    value
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::from_value(value).unwrap()
}

#[test]
fn cvss_3_vectors_give_the_base_score() {
    let assessment = assess(&record(json!({"severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    ]})));
    assert_eq!(assessment.severity, Severity::Critical);
    let cvss = assessment.cvss.unwrap();
    assert_eq!(cvss.version, "3.1");
    assert!((cvss.score - 9.8).abs() < f64::EPSILON);
}

#[test]
fn the_most_recent_cvss_version_wins() {
    let assessment = assess(&record(json!({"severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"}
    ]})));
    let cvss = assessment.cvss.unwrap();
    assert_eq!(cvss.version, "4.0");
    assert_eq!(assessment.severity, Severity::High);
}

#[test]
fn cvss_2_vectors_are_scored() {
    let assessment = assess(&record(json!({"severity": [
        {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}
    ]})));
    assert_eq!(assessment.cvss.unwrap().version, "2.0");
    assert_eq!(assessment.severity, Severity::High);
}

#[test]
fn per_package_vectors_are_used_when_the_record_has_none() {
    let assessment = assess(&record(json!({"affected": [{
        "package": {"ecosystem": "crates.io", "name": "smallvec"},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"}]
    }]})));
    assert_eq!(assessment.cvss.unwrap().version, "3.0");
    assert_eq!(assessment.severity, Severity::Medium);
}

#[test]
fn qualitative_ratings_are_the_fallback() {
    let assessment = assess(&record(json!({
        "database_specific": {"severity": "MODERATE"},
        "severity": [{"type": "Ubuntu", "score": "medium"}]
    })));
    assert!(assessment.cvss.is_none());
    assert_eq!(assessment.severity, Severity::Medium);

    let assessment = assess(&record(json!({"affected": [{
        "package": {"ecosystem": "Debian", "name": "openssl"},
        "ecosystem_specific": {"severity": "HIGH"}
    }]})));
    assert_eq!(assessment.severity, Severity::High);
}

#[test]
fn records_without_any_rating_are_unknown() {
    let assessment = assess(&record(json!({"severity": [
        {"type": "CVSS_V3", "score": "not a vector"}
    ]})));
    assert_eq!(assessment.severity, Severity::Unknown);
    assert!(assessment.cvss.is_none());
}

#[test]
fn severities_are_ordered_and_parsed() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::Low > Severity::Unknown);
    for severity in Severity::DESCENDING {
        assert_eq!(severity.as_str().parse::<Severity>().unwrap(), severity);
    }
    assert_eq!(Severity::from_score(0.0), Severity::Low);
    assert_eq!(Severity::from_score(6.9), Severity::Medium);
    assert_eq!(Severity::from_score(7.0), Severity::High);
}
