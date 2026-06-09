use crate::AppConfig;
use dioxus::prelude::*;

#[component]
pub fn StatusCard(is_active: bool) -> Element {
    let is_dark = use_context::<Signal<bool>>();
    let global_config = use_context::<Signal<AppConfig>>();
    let config = global_config.read();

    let status_text = if is_active {
        "Connected"
    } else {
        "Disconnected"
    };

    let card_style = if is_dark() {
        "bg-zinc-900 border-zinc-800 shadow-lg"
    } else {
        "bg-white border-zinc-200 shadow-md"
    };
    let label_color = if is_dark() {
        "text-zinc-400"
    } else {
        "text-zinc-500"
    };
    let dynamic_text = if is_dark() {
        "text-zinc-200"
    } else {
        "text-zinc-800"
    };

    let status_color = if is_active {
        "text-orange-500 font-semibold drop-shadow-[0_0_5px_rgba(249,115,22,0.4)]"
    } else if is_dark() {
        "text-zinc-500"
    } else {
        "text-zinc-400"
    };

    let fragmentation_mode = if config.tls_record_fragmentation {
        "TLS-Aware"
    } else {
        "Blind Chunking"
    };
    let mode_color = if config.tls_record_fragmentation {
        "text-orange-400 font-medium"
    } else if is_dark() {
        "text-zinc-500"
    } else {
        "text-zinc-400"
    };

    rsx! {
        div { class: "flex flex-col w-full gap-3 p-4 border rounded-xl transition-all duration-200 {card_style}",

            // Connection Status Row
            div { class: "flex justify-between items-center text-sm",
                span { class: "font-medium {label_color}", "Status" }
                span { class: "{status_color}", "{status_text}" }
            }

            // DNS Server Row
            div { class: "flex justify-between items-center text-sm",
                span { class: "font-medium {label_color}", "DNS Server" }
                span { class: "truncate max-w-[150px] {dynamic_text}", "{config.dns.server_url}" }
            }

            // Fragmentation Mode Row
            div { class: "flex justify-between items-center text-sm",
                span { class: "font-medium {label_color}", "Fragmentation" }
                span { class: "{mode_color}", "{fragmentation_mode}" }
            }
        }
    }
}
