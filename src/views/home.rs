use crate::{
    components::StatusCard, icons::{lucide, Icon},
    route::Route,
};
use dioxus::prelude::*;
/// The Home page component that will be rendered when the current route is `[Route::Home]`
#[component]
pub fn Home() -> Element {
    let navigator = use_navigator();
    rsx! {
        div { class: "flex flex-col flex-1 justify-between items-center",
            Icon { data: lucide::Shield, size: "128" }
            div { class: "text-sm font-bold", "No active tunnels" }
            div { class: "text-sm font-bold", "Click start to enable DPI bypass" }
            StatusCard {}
            button { class: "px-4 py-2 w-full bg-green-500 text-white rounded hover:bg-green-600 transition-colors",
                "Start"
            }
            button {
                class: "px-4 py-2 w-full bg-gray-500 text-white rounded hover:bg-gray-600 transition-colors",
                onclick: move |_| {
                    navigator.push(Route::Settings {});
                },
                "Settings"
            }
        }
    }
}
