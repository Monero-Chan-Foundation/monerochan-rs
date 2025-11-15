//! Allocators for the MONEROCHAN zkVM.
//!
//! The `embedded` allocator takes precedence if enabled.

#[cfg(not(feature = "embedded"))]
mod bump;

#[cfg(feature = "embedded")]
pub mod embedded;

#[cfg(feature = "embedded")]
pub use embedded::init;
