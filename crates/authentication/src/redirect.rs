//! The check that keeps a redirect target on this site.
//!
//! Two places build a redirect from a value the browser supplies: the `next` parameter of the
//! sign-in flow and the `Referer` of a submitted form. Both go through [`local_path`], so the
//! rule exists once.

/// `path` itself when it is safe to redirect to as a relative location, otherwise `None`.
///
/// Safe means a path starting with a single `/`: not `//host`, which browsers read as a
/// protocol-relative URL, nor `/\host`, which some browsers read the same way, and without
/// control characters (a tab or a newline inside `//` is dropped by URL parsers, and a line
/// break would split the `Location` header). The query string is kept.
pub fn local_path(path: &str) -> Option<&str> {
    (path.starts_with('/')
        && !path.starts_with("//")
        && !path.starts_with("/\\")
        && !path.chars().any(char::is_control))
    .then_some(path)
}

#[cfg(test)]
mod tests {
    use super::local_path;

    #[test]
    fn keeps_a_path_with_its_query_string() {
        assert_eq!(local_path("/"), Some("/"));
        assert_eq!(
            local_path("/projects/3?tab=findings&page=2"),
            Some("/projects/3?tab=findings&page=2")
        );
    }

    #[test]
    fn refuses_what_leaves_the_site() {
        assert_eq!(local_path("//evil.example/x"), None);
        assert_eq!(local_path("/\\evil.example"), None);
        assert_eq!(local_path("https://evil.example/"), None);
        assert_eq!(local_path("evil.example"), None);
        assert_eq!(local_path(""), None);
    }

    #[test]
    fn refuses_control_characters() {
        assert_eq!(local_path("/\t/evil.example"), None);
        assert_eq!(local_path("/ok\r\nSet-Cookie: a=b"), None);
        assert_eq!(local_path("/ok\0"), None);
    }
}
