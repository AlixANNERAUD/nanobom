//! Browser entry point: hydrates the interactive islands of the server-rendered pages.
//!
//! This crate is built for `wasm32` by cargo-leptos, separately from the server, so the `ssr`
//! and `hydrate` features of `nanobom-app` are never enabled together. Only `#[island]`
//! components run in the browser; everything else stays server-rendered HTML, and pages work
//! without this bundle.

// Unused as far as rustc can tell, but linking the app crate is what brings its islands'
// hydration functions into the bundle.
#[allow(unused_imports)]
use nanobom_app::*;

/// Called by the script Leptos adds to every page once the bundle loads.
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_islands();
}
