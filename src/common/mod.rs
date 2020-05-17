#[macro_use]
pub mod macros;
pub mod config;
mod error_kind;

pub use self::error_kind::ErrorKind;
pub use self::macros::*;
pub use failure::Error;
use grin_api;
pub use parking_lot::{Mutex, MutexGuard};
use serde::Serialize;
use std::result::Result as StdResult;
pub use std::sync::Arc;

pub const COLORED_PROMPT: &'static str = "\x1b[36mwallet713>\x1b[0m ";
#[cfg(not(target_os = "android"))]
pub const PROMPT: &'static str = "wallet713> ";

pub fn post<IN>(url: &str, api_secret: Option<String>, basic_auth_key: Option<String>, input: &IN) -> StdResult<String, grin_api::Error>
where
	IN: Serialize,
{
    let req = grin_api::client::create_post_request_ex(url, api_secret, basic_auth_key, input)?;
	let res = grin_api::client::send_request(req)?;
	Ok(res)
}
