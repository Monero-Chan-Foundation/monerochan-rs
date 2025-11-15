//! # Network Prover Builder
//!
//! This module provides a builder for the [`NetworkProver`].

use alloy_primitives::Address;

use crate::{
    network::{NetworkMode, MAINNET_RPC_URL},
    NetworkProver,
};

#[cfg(feature = "tee-2fa")]
use crate::network::retry::{self, DEFAULT_RETRY_TIMEOUT};

/// A builder for the [`NetworkProver`].
///
/// The builder is used to configure the [`NetworkProver`] before it is built.
/// All network proving now uses the monerochan network API (no direct SP1 or auction mode).
#[derive(Default)]
pub struct NetworkProverBuilder {
    pub(crate) rpc_url: Option<String>,
    pub(crate) tee_signers: Option<Vec<Address>>,
    pub(crate) network_mode: Option<NetworkMode>,
}

impl NetworkProverBuilder {
    /// Sets the RPC URL for monerochan network requests.
    ///
    /// # Details
    /// When set, the prover will use this URL for network requests. By default, the URL is
    /// read from the `NETWORK_RPC_URL` environment variable, or defaults to the monerochan
    /// production network API.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::ProverClient;
    ///
    /// let prover = ProverClient::builder().network().rpc_url("http://127.0.0.1:50051").build();
    /// ```
    #[must_use]
    pub fn rpc_url(mut self, rpc_url: &str) -> Self {
        self.rpc_url = Some(rpc_url.to_string());
        self
    }

    /// Sets the list of TEE signers, used for verifying TEE proofs.
    #[must_use]
    pub fn tee_signers(mut self, tee_signers: &[Address]) -> Self {
        self.tee_signers = Some(tee_signers.to_vec());
        self
    }

    /// Builds a [`NetworkProver`].
    ///
    /// # Details
    /// This method will build a [`NetworkProver`] that connects to the monerochan network API.
    /// The RPC URL defaults to the production monerochan network if not specified.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::ProverClient;
    ///
    /// let prover = ProverClient::builder().network().build();
    /// ```
    #[must_use]
    pub fn build(self) -> NetworkProver {
        let network_mode = self.network_mode.unwrap_or_default();

        let tee_signers = self.tee_signers.unwrap_or_else(|| {
            cfg_if::cfg_if! {
                if #[cfg(feature = "tee-2fa")] {
                    crate::utils::block_on(
                        async {
                            retry::retry_operation(
                                || async {
                                    crate::network::tee::get_tee_signers().await.map_err(Into::into)
                                },
                                Some(DEFAULT_RETRY_TIMEOUT),
                                "get tee signers"
                            ).await.expect("Failed to get TEE signers")
                        }
                    )
                } else {
                    vec![]
                }
            }
        });

        // Always use network API mode - default to mainnet
        let rpc_url = self.rpc_url
            .or_else(|| std::env::var("NETWORK_RPC_URL").ok().filter(|u| !u.is_empty()))
            .unwrap_or_else(|| MAINNET_RPC_URL.to_string());

        NetworkProver::new(network_mode, rpc_url).with_tee_signers(tee_signers)
    }
}
