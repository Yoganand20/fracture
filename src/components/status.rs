use dioxus::prelude::*;
#[component]
pub fn StatusCard() -> Element {
    rsx! {
        div { class: "flex flex-col w-full gap-2 p-4 border rounded border-gray-200",
            div { class: "text-sm text-gray-500", "DNS Server: " }
            div { class: "text-sm text-gray-500", "Status: Disconnected" }
        }
    }
}
