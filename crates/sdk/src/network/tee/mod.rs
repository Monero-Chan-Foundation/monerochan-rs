//! # TEE Integrity Proofs.
//!
//! An "integrity proof" is a signature over the outputs of the execution of a program computed
//! in a trusted execution environment (TEE).
//!
//! This acts a "2-factor authentication" for the MONEROCHAN proving system.

/// The API for the TEE server.
pub mod api;

/// The client for the TEE server.
pub mod client;

/// The MONEROCHAN TEE backend version to use.
///
/// Since this doesn't necessarily correspond to new versions of MONEROCHAN,
/// we opt to keep track of it manually here.
pub const MONEROCHAN_TEE_VERSION: u32 = 1;

/// This method will get the list of signers for the TEE server, trusting the server to honestly
/// report the list of signers.
///
/// This is a convenience method, if you want to actually verify attestions from the TEE server,
/// you need to build the enclave image yourself, and use the provided functionality from the
/// `monerochan-tee` crate to verify the signers you care about.
///
/// Signers may be cross checked from the on-chain state with attestaions stored in s3.
///
/// See <https://github.com/monero-chan-foundation/monerochan-rs-tee/blob/main/host/bin/validate_signers.rs>
///
/// # Errors
/// - [`client::ClientError::Http`] - If the request fails to send.
pub async fn get_tee_signers() -> Result<Vec<alloy_primitives::Address>, client::ClientError> {
    let client = client::Client::default();

    client.get_signers().await
}
