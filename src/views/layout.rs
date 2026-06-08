use crate::{components::AppHeader, route::Route};
use dioxus::prelude::*;

#[component]
pub fn Layout() -> Element {
    let is_dark = use_context::<Signal<bool>>();

    let layout_theme_classes = if is_dark() {
        "bg-zinc-950 text-zinc-100"
    } else {
        "bg-zinc-50 text-zinc-900"
    };

    rsx! {
        div {
            id: "layout",
            class: "flex flex-col h-full w-full overflow-hidden transition-colors duration-200 {layout_theme_classes}",

            // Unified Application Drag-Header Panel
            AppHeader {}

            // View Content Outlet Container
            div {
                class: "flex flex-col flex-1 min-h-0 w-full",
                Outlet::<Route> {}
            }
        }
    }
}
