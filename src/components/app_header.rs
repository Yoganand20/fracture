use crate::icons::{lucide, Icon};
use dioxus::desktop::window;
use dioxus::prelude::*;
#[component]
pub fn AppHeader() -> Element {
    rsx! {
        div {
            class: "flex flex-row w-full justify-between items-center px-2 py-2 bg-gray-300",
            onmousedown: move |_| {
                window().drag();
            },
            div { class: "flex flex-row gap-2 items-center",
                Icon { data: lucide::Shield }
                div { class: "text-sm font-bold text-orange-400", "Fracture" }
            }
            div { class: "flex flex-row gap-2",
                button {
                    onmousedown: move |e| e.stop_propagation(),
                    onclick: move |_| {

                        window().set_minimized(true);
                    },
                    Icon { data: lucide::Minus }
                }
                button {
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
