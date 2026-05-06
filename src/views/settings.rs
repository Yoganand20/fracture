use crate::{route::Route, AppConfig};
use dioxus::prelude::*;
/// The Settings page component that will be rendered when the current route is `[Route::Settings]`
#[component]
pub fn Settings() -> Element {
    let navigator = use_navigator();

    // 1. Grab the GLOBAL context state
    let mut global_config = use_context::<Signal<AppConfig>>();

    // 2. Create a LOCAL "draft" state initialized with the current global config
    let mut local_config = use_signal(|| global_config.read().clone());

    rsx! {
        div { style: "display: flex; flex-direction: column; gap: 15px; padding: 20px;",
            // --- TLS Fragmentation Toggle ---
            div {
                label {
                    input {
                        r#type: "checkbox",
                        checked: local_config.read().tls_record_fragmentation,
                        onchange: move |evt| {
                            local_config.write().tls_record_fragmentation = evt.checked();
                        },
                    }
                    " Enable Strict TLS Record Fragmentation (HTTPS Only)"
                }
            }

            // --- MTU Size ---
            div {
                label {
                    "ClientHello MTU Size: "
                    input {
                        r#type: "number",
                        value: "{local_config.read().fragmentation_size}",
                        onchange: move |evt| {
                            if let Ok(val) = evt.value().parse::<usize>() {
                                local_config.write().fragmentation_size = val;
                            }
                        },
                    }
                }
            }

            div { class: "flex-grow" }

            div { class: "flex flex-col gap-3 w-full",
                // --- Save Button ---
                button {
                    class: "px-4 py-2 w-full bg-blue-500 text-white rounded hover:bg-blue-600 transition-colors",
                    onclick: move |_| {
                        // Apply the draft to the GLOBAL state when clicked
                        let draft_settings = local_config.read().clone();
                        *global_config.write() = draft_settings.clone();
                        println!("Saved new global settings: {:?}", draft_settings);
                    },
                    "Save"
                }

                // --- Back Button ---
                button {
                    class: "px-4 py-2 w-full bg-gray-400 text-white rounded hover:bg-gray-500 transition-colors",
                    onclick: move |_| {
                        // If the user clicks Back without saving, the local_config is discarded
                        // and the global_config remains completely unchanged.
                        navigator.push(Route::Home {});
                    },
                    "Back"
                }
            }
        }
    }
}
