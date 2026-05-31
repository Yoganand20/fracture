use std::sync::Arc;
#[cfg(feature = "desktop")]
use std::thread;
#[cfg(feature = "desktop")]
use tokio::runtime::Runtime;
use tokio::sync::watch;

use fracture::{start_proxy_engine, AppConfig};

#[cfg(feature = "desktop")]
use dioxus::desktop::{Config, LogicalSize, WindowBuilder};
#[cfg(feature = "desktop")]
use dioxus::prelude::*;
#[cfg(feature = "desktop")]
use fracture::route::Route;

#[cfg(feature = "desktop")]
const FAVICON: Asset = asset!("/assets/favicon.ico");
#[cfg(feature = "desktop")]
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

#[cfg(feature = "desktop")]
#[cfg(target_os = "windows")]
use dioxus::desktop::tao::platform::windows::WindowBuilderExtWindows;

#[cfg(feature = "desktop")]
fn main() {
    let port = 8081;

    // Create the Watch Channel wrapped in an Arc for cheap cloning
    let initial_config = Arc::new(AppConfig::default());
    let (tx, rx) = watch::channel(initial_config.clone());

    // Spawn the background Proxy Engine
    thread::spawn(move || {
        let rt: Runtime = Runtime::new().expect("Failed to create Tokio runtime");

        rt.block_on(async {
            if let Err(e) = start_proxy_engine(port, initial_config, rx).await {
                eprintln!("✗ Proxy error: {}", e);
            }
        });
    });

    // Spawn the Dioxus Desktop UI
    let mut window = WindowBuilder::new()
        .with_decorations(false)
        .with_transparent(true)
        .with_undecorated_shadow(false)
        .with_inner_size(LogicalSize::new(300.0, 600.0))
        .with_resizable(false);

    #[cfg(target_os = "windows")]
    {
        window = window.with_undecorated_shadow(false);
    }

    let config = Config::new().with_window(window);

    // INJECT the Transmitter into the Dioxus App context!
    LaunchBuilder::desktop()
        .with_cfg(config)
        .with_context(tx)
        .launch(App);

    // Cleanup when UI window is closed
    println!("UI Closed. Disabling system proxy...");
    let _ = fracture::os::proxy::SystemProxy::disable();
}

/// App is the main component of our app.
#[cfg(feature = "desktop")]
#[component]
fn App() -> Element {
    // Read the global watch channel sender that was passed into LaunchBuilder
    let tx = use_context::<tokio::sync::watch::Sender<Arc<AppConfig>>>();

    // Provide the initial state to the rest of the Dioxus UI
    use_context_provider(|| Signal::new((*tx.borrow()).as_ref().clone()));

    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        div { class: "w-screen h-screen bg-white rounded-2xl overflow-hidden border-2",
            Router::<Route> {}
        }
    }
}
