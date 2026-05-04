use crate::route::Route;
use dioxus::prelude::*;
/// The Settings page component that will be rendered when the current route is `[Route::Settings]`
#[component]
pub fn Settings() -> Element {
    let navigator = use_navigator();
    rsx! {
        div { class: "flex flex-col flex-1 justify-between",
            div { class: "text-lg font-bold text-center", "Tunnel Settings" }
            div { class: "flex flex-col gap-2",
                label { class: "text-sm font-bold text-gray-700", "Custom DNS Server" }
                input {
                    class: "border rounded px-3 py-2 text-sm w-full outline-none focus:border-green-500",
                    placeholder: "e.g., 1.1.1.1",
                    r#type: "text",
                }
            }
            div { class: "flex flex-col gap-2",
                label { class: "text-sm font-bold text-gray-700", "Local Port" }
                input {
                    class: "border rounded px-3 py-2 text-sm w-full outline-none focus:border-green-500",
                    placeholder: "e.g., 8080",
                    r#type: "number",
                }
            }
            div { class: "flex-grow" }
            div { class: "flex flex-col gap-3 w-full",
                button { class: "px-4 py-2 w-full bg-blue-500 text-white rounded hover:bg-blue-600 transition-colors",
                    "Save"
                }
                button {
                    class: "px-4 py-2 w-full bg-gray-400 text-white rounded hover:bg-gray-500 transition-colors",
                    onclick: move |_| {
                        navigator.push(Route::Home {});
                    },
                    "Back"
                }
            }
        }
    }
}
