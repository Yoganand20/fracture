use crate::{components::AppHeader, route::Route};
use dioxus::prelude::*;
/// This layout component wraps the UI of [Route::Home] / [Route::Settings] with a common AppHeader.
#[component]
pub fn Layout() -> Element {
    rsx! {
        div { id: "layout", class: "flex flex-col h-screen w-screen",
            AppHeader {}
            div { class: "p-4 flex flex-col flex-1", Outlet::<Route> {} }
        }
    }
}
