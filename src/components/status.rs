use dioxus::prelude::*;

use crate::AppConfig;
#[component]
pub fn StatusCard(is_active: bool) -> Element {
    let global_config = use_context::<Signal<AppConfig>>();
    let config = global_config.read();

    let status_text = if is_active {
        "Connected"
    } else {
        "Disconnected"
    };
    let status_color = if is_active {
        "text-green-500 font-semibold"
    } else {
        "text-gray-400"
    };
    let fragmentation_mode = if config.tls_record_fragmentation {
        "TLS-Aware"
    } else {
        "Blind Chunking"
    };
    let mode_color = if config.tls_record_fragmentation {
        "text-orange-500 font-medium"
    } else {
        "text-gray-600"
    };
    rsx! {
        div { class: "flex flex-col w-full gap-3 p-4 my-6 bg-gray-50 border rounded-xl border-gray-200 shadow-sm",

            // Connection Status Row
            div { class: "flex justify-between items-center text-sm",
                span { class: "text-gray-500 font-medium", "Status" }
                span { class: "{status_color}", "{status_text}" }
            }

            // DNS Server Row
            div { class: "flex justify-between items-center text-sm",
                span { class: "text-gray-500 font-medium", "DNS Server" }
                span { class: "text-gray-700 truncate max-w-[150px]", "{config.dns.server_url}" }
            }

            // Fragmentation Mode Row
            div { class: "flex justify-between items-center text-sm",
                span { class: "text-gray-500 font-medium", "Fragmentation" }
                span { class: "{mode_color}", "{fragmentation_mode}" }
            }
        }
    }
}
