use crate::{dns::resolver::DnsType, route::Route, AppConfig};
use dioxus::prelude::*;
use std::sync::Arc;

#[component]
pub fn Settings() -> Element {
    let navigator = use_navigator();
    let mut global_config = use_context::<Signal<AppConfig>>();
    let mut local_config = use_signal(|| global_config.read().clone());

    let tx = use_context::<tokio::sync::watch::Sender<Arc<AppConfig>>>();

    let current_dns_type = match local_config.read().dns.dns_type {
        DnsType::Https => "Https",
        DnsType::Tls => "Tls",
        DnsType::Quic => "Quic",
        DnsType::Unencrypted => "Unencrypted",
    };

    rsx! {
        div { class: "flex flex-col h-full w-full bg-gray-50 overflow-hidden",

            // 1. CONTENT DIV: Scrolls internally
            div { class: "flex-1 overflow-y-auto p-4 space-y-4",

                // 1. General Settings Card
                div { class: "bg-white p-4 rounded-xl shadow-sm border border-gray-100",
                    h3 { class: "text-sm font-bold text-gray-700 mb-3", "General" }
                    label { class: "flex items-center space-x-2 text-sm",
                        input {
                            r#type: "checkbox",
                            class: "rounded text-blue-500 focus:ring-blue-500",
                            checked: local_config.read().https_only,
                            onchange: move |evt| local_config.write().https_only = evt.checked(),
                        }
                        span { "Block Insecure HTTP (HTTPS Only)" }
                    }
                }

                // 2. DPI Evasion Card
                div { class: "bg-white p-4 rounded-xl shadow-sm border border-gray-100",
                    h3 { class: "text-sm font-bold text-gray-700 mb-3", "DPI Evasion Engine" }

                    label { class: "flex items-center space-x-2 text-sm mb-3",
                        input {
                            r#type: "checkbox",
                            class: "rounded text-blue-500 focus:ring-blue-500",
                            checked: local_config.read().tls_record_fragmentation,
                            onchange: move |evt| local_config.write().tls_record_fragmentation = evt.checked(),
                        }
                        span { "Strict TLS Record Fragmentation" }
                    }

                    div { class: "flex flex-col space-y-1",
                        label { class: "text-xs text-gray-500", "Fragmentation Size (MTU)" }
                        input {
                            r#type: "number",
                            class: "border rounded p-2 text-sm w-full",
                            value: "{local_config.read().fragmentation_size}",
                            onchange: move |evt| {
                                if let Ok(val) = evt.value().parse::<usize>() {
                                    local_config.write().fragmentation_size = val;
                                }
                            },
                        }
                    }
                }

                // 3. DNS Resolver Card
                div { class: "bg-white p-4 rounded-xl shadow-sm border border-gray-100 space-y-3",
                    h3 { class: "text-sm font-bold text-gray-700 mb-1", "DNS Resolver" }

                    // DNS Type Dropdown
                    div { class: "flex flex-col space-y-1",
                        label { class: "text-xs text-gray-500", "Protocol" }
                        select {
                            class: "border rounded p-2 text-sm bg-white",
                            onchange: move |evt| {
                                let dt = match evt.value().as_str() {
                                    "Https" => DnsType::Https,
                                    "Tls" => DnsType::Tls,
                                    "Quic" => DnsType::Quic,
                                    _ => DnsType::Unencrypted,
                                };
                                local_config.write().dns.dns_type = dt;
                            },
                            option {
                                value: "Https",
                                selected: current_dns_type == "Https",
                                "DoH (HTTPS)"
                            }
                            option {
                                value: "Tls",
                                selected: current_dns_type == "Tls",
                                "DoT (TLS)"
                            }
                            option {
                                value: "Quic",
                                selected: current_dns_type == "Quic",
                                "DoQ (QUIC)"
                            }
                            option {
                                value: "Unencrypted",
                                selected: current_dns_type == "Unencrypted",
                                "Unencrypted (UDP/TCP)"
                            }
                        }
                    }

                    // Server URL
                    div { class: "flex flex-col space-y-1",
                        label { class: "text-xs text-gray-500", "Server URL (SNI)" }
                        input {
                            r#type: "text",
                            class: "border rounded p-2 text-sm",
                            placeholder: "e.g., cloudflare-dns.com",
                            value: "{local_config.read().dns.server_url}",
                            onchange: move |evt| local_config.write().dns.server_url = evt.value().clone(),
                        }
                    }

                    // IPs (Comma separated)
                    div { class: "flex flex-col space-y-1",
                        label { class: "text-xs text-gray-500", "Server IPs (Comma separated)" }
                        input {
                            r#type: "text",
                            class: "border rounded p-2 text-sm",
                            placeholder: "1.1.1.1, 1.0.0.1",
                            value: "{local_config.read().dns.ips.join(\", \")}",
                            onchange: move |evt| {
                                let ips: Vec<String> = evt
                                    .value()
                                    .split(',')
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect();
                                local_config.write().dns.ips = ips;
                            },
                        }
                    }

                    // Port and Cache side-by-side
                    div { class: "flex space-x-2",
                        div { class: "flex flex-col space-y-1 w-1/2",
                            label { class: "text-xs text-gray-500", "Port" }
                            input {
                                r#type: "number",
                                class: "border rounded p-2 text-sm",
                                value: "{local_config.read().dns.port}",
                                onchange: move |evt| {
                                    if let Ok(val) = evt.value().parse::<u16>() {
                                        local_config.write().dns.port = val;
                                    }
                                },
                            }
                        }
                        div { class: "flex flex-col space-y-1 w-1/2",
                            label { class: "text-xs text-gray-500", "Cache Size" }
                            input {
                                r#type: "number",
                                class: "border rounded p-2 text-sm",
                                value: "{local_config.read().dns.cache_size}",
                                onchange: move |evt| {
                                    if let Ok(val) = evt.value().parse::<u64>() {
                                        local_config.write().dns.cache_size = val;
                                    }
                                },
                            }
                        }
                    }
                }
            }

            // 2. BOTTOM NAVIGATION: Fixed naturally at the bottom
            div { class: "p-4 bg-white border-t flex flex-col gap-2 shrink-0 z-10 shadow-[0_-4px_6px_-1px_rgba(0,0,0,0.05)]",
                button {
                    class: "px-4 py-2 w-full bg-blue-500 text-white font-semibold rounded-lg hover:bg-blue-600 transition",
                    onclick: move |_| {
                        let draft_settings = local_config.read().clone();

                        // 1. Update the local Dioxus UI Signal
                        *global_config.write() = draft_settings.clone();

                        // 2. Broadcast the new config to the background Tokio engine
                        if let Err(e) = tx.send(Arc::new(draft_settings)) {
                            eprintln!("Failed to send config to proxy engine: {}", e);
                        } else {
                            println!("Saved settings and instantly synced with Proxy Engine.");
                        }
                    },
                    "Save Configuration"
                }
                button {
                    class: "px-4 py-2 w-full bg-gray-200 text-gray-700 font-semibold rounded-lg hover:bg-gray-300 transition",
                    onclick: move |_| {
                        navigator.push(Route::Home {});
                    },
                    "Go Back"
                }
            }
        }
    }
}
