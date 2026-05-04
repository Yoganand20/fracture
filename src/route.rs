use crate::views::{Home, Layout, Settings};
use dioxus::prelude::*;
/// The Route enum is used to define the structure of internal routes in our app. All route enums need to derive
/// the [`Routable`] trait, which provides the necessary methods for the router to work.
#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
pub(crate) enum Route {
    #[layout(Layout)]
    #[route("/")]
    Home {},
    #[route("/settings")]
    Settings {},
}
