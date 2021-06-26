#[macro_use]
pub mod macros;
pub mod config;
mod error_kind;

pub use self::error_kind::ErrorKind;
pub use self::macros::*;
pub use failure::Error;
pub use parking_lot::{Mutex, MutexGuard};
pub use std::sync::Arc;

pub const COLORED_PROMPT: &'static str = "\x1b[36mwallet713>\x1b[0m ";
#[cfg(not(target_os = "android"))]
pub const PROMPT: &'static str = "wallet713> ";
