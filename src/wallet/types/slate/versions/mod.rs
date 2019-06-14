#[allow(missing_docs)]
pub mod v0;
#[allow(missing_docs)]
pub mod v1;
#[allow(missing_docs)]
pub mod v2;

/// The most recent version of the slate
pub const CURRENT_SLATE_VERSION: u16 = 2;

/// The grin block header this slate is intended to be compatible with
pub const GRIN_BLOCK_HEADER_VERSION: u16 = 1;
