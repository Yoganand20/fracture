use dioxus::prelude::*;
use std::sync::Arc;

use crate::{
    components::StatusCard,
    icons::{lucide, Icon},
    os::proxy::SystemProxy,
    route::Route,
    ProxyController,
};

#[component]
pub fn Home() -> Element {
    let navigator = use_navigator();
    let is_dark = use_context::<Signal<bool>>();
    let proxy_state = use_context::<Arc<ProxyController>>();
    let mut is_active = use_signal(|| proxy_state.is_active());

    let toggle_proxy = move |_| {
        if is_active() {
            if let Err(e) = SystemProxy::disable() {
                eprintln!("Failed to disable proxy: {}", e);
                return;
            }
            proxy_state.set_active(false);
            is_active.set(false);
        } else {
            if let Err(e) = SystemProxy::enable(proxy_state.port()) {
                eprintln!("Failed to enable proxy: {}", e);
                return;
            }
            proxy_state.set_active(true);
            is_active.set(true);
        }
    };

    rsx! {
        div { class: "flex flex-col h-full w-full overflow-hidden",

            // 1. Core View Container: Occupies all remaining available space, completely hidden scrollbars
            div { class: "flex-1 p-4 flex flex-col justify-between items-center min-h-0 overflow-hidden",

                // Sub-Container A: Groups the shield and dynamic text right at the very top
                div { class: "w-full flex flex-col justify-start items-center space-y-5 pt-2",

                    // Central Indicator (Always First at the top)
                    div { class: "py-1",
                        Icon {
                            data: lucide::Shield,
                            size: "120",
                            class: if is_active() {
                                "text-orange-500 drop-shadow-[0_0_15px_rgba(249,115,22,0.4)] transition-all duration-300"
                            } else if is_dark() {
                                "text-zinc-800 transition-all duration-300"
                            } else {
                                "text-zinc-300 transition-all duration-300"
                            },
                        }
                    }

                    // Header Metrics Description Texts (Always sits right below the Shield)
                    div { class: "text-center space-y-1",
                        h2 { class: "text-xl font-extrabold tracking-tight " .to_owned() + if is_dark() { "text-zinc-100" } else { "text-zinc-900" },
                            if is_active() { "Tunnel is Active" } else { "No Active Tunnels" }
                        }
                        p { class: "text-xs px-6 " .to_owned() + if is_dark() { "text-zinc-400" } else { "text-zinc-500" },
                            if is_active() { "DPI bypass is currently routing your traffic." } else { "Click start to enable DPI bypass security protections." }
                        }
                    }
                }

                // Sub-Container B: Sits naturally anchored at the baseline of the core container right above the footer
                div { class: "w-full pb-2 justify-end",
                    StatusCard { is_active: is_active() }
                }
            }

            // 2. Footer action button block layout (Anchored statically to the window bottom)
            div {
                class: "h-[160px] w-full p-4 border-t flex flex-col justify-center gap-3 shrink-0 z-10 transition-colors duration-200 " .to_owned() +
                    if is_dark() { "bg-zinc-900 border-zinc-800" } else { "bg-white border-zinc-200 shadow-[0_-4px_12px_rgba(0,0,0,0.02)]" },

                button {
                    class: if is_active() {
                        "px-4 py-3 w-full bg-transparent border-2 border-orange-500/60 text-orange-500 font-bold rounded-xl hover:bg-orange-500/10 transition-all"
                    } else {
                        "px-4 py-3 w-full bg-orange-500 text-zinc-950 font-bold rounded-xl hover:bg-orange-600 shadow-[0_0_15px_rgba(249,115,22,0.25)] transition-all"
                    },
                    onclick: toggle_proxy,
                    if is_active() { "Stop Interception" } else { "Start Engine" }
                }

                button {
                    class: "px-4 py-3 w-full font-bold rounded-xl transition-colors " .to_owned() +
                        if is_dark() { "bg-zinc-800 text-zinc-300 hover:bg-zinc-700 hover:text-white" } else { "bg-zinc-100 text-zinc-700 hover:bg-zinc-200 hover:text-zinc-950" },
                    onclick: move |_| {
                        navigator.push(Route::Settings {});
                    },
                    "Configuration"
                }
            }
        }
    }
}
