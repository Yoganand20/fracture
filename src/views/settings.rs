use crate::{dns::resolver::DnsType, route::Route, AppConfig};
use dioxus::prelude::*;
use std::sync::Arc;

#[component]
pub fn Settings() -> Element {
    let navigator = use_navigator();
    let is_dark = use_context::<Signal<bool>>();
    let mut global_config = use_context::<Signal<AppConfig>>();
    let mut local_config = use_signal(|| global_config.read().clone());
    let tx = use_context::<tokio::sync::watch::Sender<Arc<AppConfig>>>();

    let current_dns_type = local_config.read().dns.dns_type.to_string();

    let card_style = if is_dark() {
        "bg-zinc-900 border-zinc-800 shadow-md"
    } else {
        "bg-white border-zinc-200 shadow-sm"
    };
    let input_style = if is_dark() {
        "bg-zinc-950 border-zinc-700 text-zinc-100 focus:border-orange-500"
    } else {
        "bg-zinc-50 border-zinc-300 text-zinc-900 focus:border-orange-500"
    };
    let label_style = if is_dark() {
        "text-zinc-400"
    } else {
        "text-zinc-500"
    };
    let text_style = if is_dark() {
        "text-zinc-200"
    } else {
        "text-zinc-800"
    };

    let scrollbar_style = "overflow-y-auto [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:rounded-full " .to_owned() + 
        if is_dark() { "[&::-webkit-scrollbar-thumb]:bg-zinc-800" } else { "[&::-webkit-scrollbar-thumb]:bg-zinc-300" };

    rsx! {
        div { class: "flex flex-col h-full w-full overflow-hidden",

            // Content Scroller Body Frame
            div { class: "flex-1 p-4 space-y-4 rounded-xl min-h-0 {scrollbar_style}",

                // General Settings Card
                div { class: "p-4 rounded-xl border space-y-4 transition-colors {card_style}",
                    h3 { class: "text-xs uppercase tracking-wider font-extrabold {label_style}",
                        "General App Settings"
                    }
                    div { class: "flex space-x-3",
                        div { class: "flex flex-col space-y-1.5 w-1/2",
                            label { class: "text-xs font-medium {label_style}", "Proxy Listening Port" }
                            input {
                                r#type: "number",
                                class: "border rounded-lg p-2.5 text-sm focus:outline-none focus:ring-1 focus:ring-orange-500 transition-all {input_style}",
                                value: "{local_config.read().proxy_port}",
                                onchange: move |evt| {
                                    if let Ok(val) = evt.value().parse::<u16>() {
                                        local_config.write().proxy_port = val;
                                    }
                                },
                            }
                        }
                        div { class: "flex flex-col space-y-1.5 w-1/2",
                            label { class: "text-xs font-medium {label_style}", "Console Log Level" }
                            select {
                                class: "border rounded-lg p-2.5 text-sm focus:outline-none focus:border-orange-500 transition-colors cursor-pointer {input_style}",
                                onchange: move |evt| local_config.write().log_level = evt.value().clone(),
                                option {
                                    value: "trace",
                                    selected: local_config.read().log_level == "trace",
                                    "Trace"
                                }
                                option {
                                    value: "debug",
                                    selected: local_config.read().log_level == "debug",
                                    "Debug"
                                }
                                option {
                                    value: "info",
                                    selected: local_config.read().log_level == "info",
                                    "Info"
                                }
                                option {
                                    value: "warn",
                                    selected: local_config.read().log_level == "warn",
                                    "Warn"
                                }
                                option {
                                    value: "error",
                                    selected: local_config.read().log_level == "error",
                                    "Error"
                                }
                                option {
                                    value: "off",
                                    selected: local_config.read().log_level == "off",
                                    "Off"
                                }
                            }
                        }
                    }

                    label { class: "flex items-center space-x-3 text-sm cursor-pointer {text_style}",
                        input {
                            r#type: "checkbox",
                            class: "w-4 h-4 rounded accent-orange-500 cursor-pointer",
                            checked: local_config.read().https_only,
                            onchange: move |evt| local_config.write().https_only = evt.checked(),
                        }
                        span { "Block Insecure HTTP (HTTPS Only)" }
                    }
                }

                // DPI Evasion Card
                div { class: "p-4 rounded-xl border space-y-4 transition-colors {card_style}",
                    h3 { class: "text-xs uppercase tracking-wider font-extrabold {label_style}",
                        "DPI Evasion Engine"
                    }

                    label { class: "flex items-center space-x-3 text-sm cursor-pointer {text_style}",
                        input {
                            r#type: "checkbox",
                            class: "w-4 h-4 rounded accent-orange-500 cursor-pointer",
                            checked: local_config.read().tls_record_fragmentation,
                            onchange: move |evt| local_config.write().tls_record_fragmentation = evt.checked(),
                        }
                        span { "Strict TLS Record Fragmentation" }
                    }

                    div { class: "flex flex-col space-y-1.5",
                        label { class: "text-xs font-medium {label_style}",
                            "Fragmentation Size (MTU bytes)"
                        }
                        input {
                            r#type: "number",
                            class: "border rounded-lg p-2.5 text-sm w-full focus:outline-none focus:ring-1 focus:ring-orange-500 transition-all {input_style}",
                            value: "{local_config.read().fragmentation_size}",
                            onchange: move |evt| {
                                if let Ok(val) = evt.value().parse::<usize>() {
                                    local_config.write().fragmentation_size = val;
                                }
                            },
                        }
                    }
                }

                // DNS Resolver Card
                div { class: "p-4 rounded-xl border space-y-4 transition-colors {card_style}",
                    h3 { class: "text-xs uppercase tracking-wider font-extrabold {label_style}",
                        "DNS Resolver"
                    }

                    div { class: "flex flex-col space-y-1.5",
                        label { class: "text-xs font-medium {label_style}", "Protocol" }
                        select {
                            class: "border rounded-lg p-2.5 text-sm focus:outline-none focus:border-orange-500 transition-colors cursor-pointer {input_style}",
                            onchange: move |evt| {
                                let dt = evt.value().parse::<DnsType>().unwrap_or(DnsType::Unencrypted);
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

                    div { class: "flex flex-col space-y-1.5",
                        label { class: "text-xs font-medium {label_style}", "Server URL (SNI)" }
                        input {
                            r#type: "text",
                            class: "border rounded-lg p-2.5 text-sm focus:outline-none focus:ring-1 focus:ring-orange-500 transition-all placeholder-zinc-500 {input_style}",
                            placeholder: "e.g., cloudflare-dns.com",
                            value: "{local_config.read().dns.server_url}",
                            onchange: move |evt| local_config.write().dns.server_url = evt.value().clone(),
                        }
                    }

                    div { class: "flex flex-col space-y-1.5",
                        label { class: "text-xs font-medium {label_style}",
                            "Server IPs (Comma separated)"
                        }
                        input {
                            r#type: "text",
                            class: "border rounded-lg p-2.5 text-sm focus:outline-none focus:ring-1 focus:ring-orange-500 transition-all placeholder-zinc-500 {input_style}",
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

                    div { class: "flex space-x-3",
                        div { class: "flex flex-col space-y-1.5 w-1/2",
                            label { class: "text-xs font-medium {label_style}", "Port" }
                            input {
                                r#type: "number",
                                class: "border rounded-lg p-2.5 text-sm focus:outline-none focus:ring-1 focus:ring-orange-500 transition-all {input_style}",
                                value: "{local_config.read().dns.port}",
                                onchange: move |evt| {
                                    if let Ok(val) = evt.value().parse::<u16>() {
                                        local_config.write().dns.port = val;
                                    }
                                },
                            }
                        }
                        div { class: "flex flex-col space-y-1.5 w-1/2",
                            label { class: "text-xs font-medium {label_style}", "Cache Size" }
                            input {
                                r#type: "number",
                                class: "border rounded-lg p-2.5 text-sm focus:outline-none focus:ring-1 focus:ring-orange-500 transition-all {input_style}",
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

            // Bottom Action Control Panel Drawer
            div {
                class: "h-[160px] w-full p-4 border-t flex flex-col justify-center gap-3 shrink-0 z-10 transition-colors duration-200 "
                    .to_owned()
                    + if is_dark() {
                        "bg-zinc-900 border-zinc-800"
                    } else {
                        "bg-white border-zinc-200 shadow-[0_-4px_12px_rgba(0,0,0,0.02)]"
                    },

                button {
                    class: "px-4 py-3 w-full bg-orange-500 text-zinc-950 font-bold rounded-xl hover:bg-orange-600 shadow-[0_0_10px_rgba(249,115,22,0.2)] transition-colors",
                    onclick: move |_| {
                        let draft_settings = local_config.read().clone();
                        *global_config.write() = draft_settings.clone();

                        if let Err(e) = tx.send(Arc::new(draft_settings)) {
                            eprintln!("Failed to send config to proxy engine: {}", e);
                        } else {
                            println!("Saved settings and instantly synced with Proxy Engine.");
                            navigator.push(Route::Home {});
                        }
                    },
                    "Save & Apply"
                }
                button {
                    class: "px-4 py-3 w-full font-bold rounded-xl transition-colors ".to_owned()
                        + if is_dark() {
                            "bg-zinc-800 text-zinc-300 hover:bg-zinc-700 hover:text-white"
                        } else {
                            "bg-zinc-100 text-zinc-700 hover:bg-zinc-200 hover:text-zinc-950"
                        },
                    onclick: move |_| {
                        navigator.push(Route::Home {});
                    },
                    "Cancel"
                }
            }
        }
    }
}
