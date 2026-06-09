use dioxus::desktop::{Config, LogicalSize, WindowBuilder};
use dioxus::prelude::*;
use std::sync::Arc;

use fracture::os::proxy::SystemProxy;
use fracture::route::Route;
use fracture::{spawn_background_engine, AppConfig};

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

#[cfg(target_os = "windows")]
use dioxus::desktop::tao::platform::windows::WindowBuilderExtWindows;

fn main() {
    let initial_config = Arc::new(AppConfig::default());

    let _engine = spawn_background_engine(initial_config);

    let window = WindowBuilder::new()
        .with_decorations(false)
        .with_transparent(true)
        .with_undecorated_shadow(false)
        .with_inner_size(LogicalSize::new(310.0, 620.0))
        .with_resizable(false);

    let config = Config::new().with_window(window);

    LaunchBuilder::desktop()
        .with_cfg(config)
        .with_context(_engine.config_tx.clone())
        .with_context(_engine.proxy_state.clone())
        .launch(App);

    println!("UI Window Closed. Cleaning up network allocations...");

    if let Err(e) = SystemProxy::disable() {
        eprintln!("⚠ Reverting system proxy failed during exit: {}", e);
    }

    _engine.proxy_state.set_active(false);
    println!("Fracture terminated cleanly.");
}

/// Main UI Component Wrapper
#[component]
fn App() -> Element {
    let tx = use_context::<tokio::sync::watch::Sender<Arc<AppConfig>>>();

    use_context_provider(|| Signal::new((*tx.borrow()).as_ref().clone()));

    let is_dark = use_context_provider(|| Signal::new(true));

    let window_border_class = if is_dark() {
        "border-zinc-800 shadow-2xl"
    } else {
        "border-zinc-200 shadow-xl"
    };

    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }

        div { class: "w-screen h-screen rounded-xl overflow-hidden border flex flex-col select-none transition-colors duration-200 {window_border_class}",
            Router::<Route> {}
        }
    }
}
