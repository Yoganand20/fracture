use std::sync::atomic::Ordering;

use crate::{
    components::StatusCard,
    icons::{lucide, Icon},
    os::proxy::SystemProxy,
    route::Route,
    IS_PROXY_ACTIVE,
};
use dioxus::prelude::*;
/// The Home page component that will be rendered when the current route is `[Route::Home]`
#[component]
pub fn Home() -> Element {
    let navigator = use_navigator();
    let mut is_active = use_signal(|| IS_PROXY_ACTIVE.load(Ordering::Relaxed));

    let toggle_proxy = move |_| {
        if is_active() {
            // Turn OFF
            if let Err(e) = SystemProxy::disable() {
                eprintln!("Failed to disable proxy: {}", e);
            }
            IS_PROXY_ACTIVE.store(false, Ordering::Relaxed);
            is_active.set(false);
        } else {
            // Turn ON (Using the port 8081 we defined in main)
            if let Err(e) = SystemProxy::enable(8081) {
                eprintln!("Failed to enable proxy: {}", e);
            }
            IS_PROXY_ACTIVE.store(true, Ordering::Relaxed);
            is_active.set(true);
        }
    };
    rsx! {
        div { class: "flex flex-col flex-1 justify-between items-center",
            Icon {
                data: lucide::Shield,
                size: "128",
                // Changes color to Orange when active
                class: if is_active() { "text-orange-400" } else { "text-gray-400" },
            }

            // Dynamic Text
            div { class: "text-lg font-bold mt-4",
                if is_active() {
                    "Tunnel is Active"
                } else {
                    "No active tunnels"
                }
            }
            div { class: "text-sm text-gray-500 text-center px-4",
                if is_active() {
                    "DPI bypass is currently routing your traffic."
                } else {
                    "Click start to enable DPI bypass."
                }
            }

            StatusCard {}

            // Start/Stop Button
            button {
                class: if is_active() { "px-4 py-2 w-full bg-white text-orange-400 font-bold rounded hover:text-orange-500 transition-colors mt-4" } else { "px-4 py-2 w-full bg-orange-400 text-white font-bold rounded hover:bg-orange-500 transition-colors mt-4" },
                onclick: toggle_proxy,
                if is_active() {
                    "Stop"
                } else {
                    "Start"
                }
            }

            // Settings Button
            button {
                class: "px-4 py-2 w-full bg-gray-500 text-white font-bold rounded hover:bg-gray-600 transition-colors mt-2",
                onclick: move |_| {
                    navigator.push(Route::Settings {});
                },
                "Settings"
            }
        }
    }
}
