use crate::icons::{lucide, Icon};
use dioxus::desktop::window;
use dioxus::prelude::*;

#[component]
pub fn AppHeader() -> Element {
    let mut is_dark = use_context::<Signal<bool>>();

    // Dynamic header styles mapping based on selected theme
    let header_bg = if is_dark() {
        "bg-zinc-950 border-zinc-800"
    } else {
        "bg-zinc-100 border-zinc-200"
    };
    let text_color = if is_dark() {
        "text-zinc-100"
    } else {
        "text-zinc-900"
    };
    let utility_btn = if is_dark() {
        "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"
    } else {
        "text-zinc-500 hover:bg-zinc-200 hover:text-zinc-900"
    };

    rsx! {
        div {
            class: "flex flex-row w-full justify-between items-center px-3 py-2 border-b cursor-move select-none transition-colors duration-200 {header_bg}",
            onmousedown: move |_| {
                window().drag();
            },

            // App Branding Block
            div { class: "flex flex-row gap-2 items-center pointer-events-none",
                div { class: "text-orange-500",
                    Icon { data: lucide::Shield }
                }
                div { class: "text-sm font-bold tracking-wide transition-colors {text_color}", "Fracture" }
            }

            // Window & Utility System Controls Group
            div { class: "flex flex-row gap-0.5 items-center",

                // Dynamic Theme Toggle Button
                button {
                    class: "p-1 rounded transition-colors cursor-pointer {utility_btn}",
                    onmousedown: move |e| e.stop_propagation(), // Block window drag initiation
                    onclick: move |_| is_dark.set(!is_dark()),
                    title: "Toggle Theme Profile",
                    Icon {
                        data: if is_dark() { lucide::Sun } else { lucide::Moon },
                        size: "16"
                    }
                }

                // Window Minimizer Control
                button {
                    class: "p-1 rounded transition-colors cursor-pointer {utility_btn}",
                    onmousedown: move |e| e.stop_propagation(),
                    onclick: move |_| {
                        window().set_minimized(true);
                    },
                    Icon { data: lucide::Minus }
                }

                // Window Terminator Control
                button {
                    class: if is_dark() {
                        "p-1 rounded text-zinc-400 hover:bg-red-500/20 hover:text-red-400 transition-colors cursor-pointer"
                    } else {
                        "p-1 rounded text-zinc-500 hover:bg-red-500/10 hover:text-red-600 transition-colors cursor-pointer"
                    },
                    onmousedown: move |e| e.stop_propagation(),
                    onclick: move |_| {
                        window().close();
                    },
                    Icon { data: lucide::X }
                }
            }
        }
    }
}
