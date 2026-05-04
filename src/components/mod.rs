//! The components module contains all shared components for our app. Components are the building blocks of dioxus apps.
//! They can be used to defined common UI elements like buttons, forms, and modals. In this template, we define a AppHeader
//! component  to be used in our app.
mod app_header;
mod status;
pub use app_header::AppHeader;
pub use status::StatusCard;
