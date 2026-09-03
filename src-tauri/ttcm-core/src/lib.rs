//! Pure, platform-independent core logic for TryToCatchMe.
//!
//! No Tauri / OS dependencies here so it stays unit-testable and reusable on other
//! platforms (e.g. a future Android target).

pub mod config;
pub mod links;
pub mod routing;
