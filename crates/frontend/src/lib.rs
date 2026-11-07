//! Browser entry point: hydrates the interactive islands of the server-rendered pages.

#[allow(unused_imports)]
use nanobom_app::*;

#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_islands();
}
