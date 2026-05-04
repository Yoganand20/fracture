mod components;
mod icons;
mod route;
mod views;
#[cfg(target_os = "windows")]
use dioxus::desktop::tao::platform::windows::WindowBuilderExtWindows;
use dioxus::desktop::{Config, LogicalSize, WindowBuilder};
use dioxus::prelude::*;
use route::Route;
const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");
fn main() {
    let mut window = WindowBuilder::new()
        .with_decorations(false)
        .with_transparent(true)
        .with_undecorated_shadow(false)
        .with_inner_size(LogicalSize::new(300.0, 500.0))
        .with_resizable(false);
    #[cfg(target_os = "windows")]
    {
        window = window.with_undecorated_shadow(false);
    }
    let config = Config::new().with_window(window);
    LaunchBuilder::desktop().with_cfg(config).launch(App);
}
/// App is the main component of our app. Components are the building blocks of dioxus apps. Each component is a function
/// that takes some props and returns an Element. In this case, App takes no props because it is the root of our app.
#[component]
fn App() -> Element {
    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        div { class: "w-screen h-screen bg-white rounded-2xl overflow-hidden border-2",
            Router::<Route> {}
        }
    }
}
