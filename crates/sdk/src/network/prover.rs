//! # Network Prover
//!
//! This module provides an implementation of the [`crate::Prover`] trait that can generate proofs
//! on a remote RPC server.

use std::time::{Duration, Instant};

use super::prove::NetworkProveBuilder;
use crate::{
    cpu::{execute::CpuExecuteBuilder, CpuProver},
    network::{
        proto::types::FulfillmentStrategy,
        Error, NetworkMode,
    },
    prover::verify_proof,
    MONEROCHANProofMode, MONEROCHANProofWithPublicValues, MONEROCHANProvingKey,
    MONEROCHANVerifyingKey, ProofFromNetwork, Prover,
};

use alloy_primitives::{Address, B256};
use std::str::FromStr;
use anyhow::{anyhow, Context, Result};
use bincode;
use hex;
use monerochan_core_executor::MONEROCHANContextBuilder;
use monerochan_core_machine::io::MONEROCHANStdin;
use crate::network::proto::api::network_client::NetworkClient;
use crate::network::proto::api::{
    ClientAuth, FulfillmentStrategy as NetworkApiFulfillmentStrategy, 
    GetProofStatusRequest, GetProofStatusResponse, JobStatus, ProofMode as NetworkApiProofMode, RequestProofRequest,
};
use monerochan_prover::{
    components::CpuProverComponents, HashableKey, MONEROCHANProver,
};
use tonic::transport::Channel;
use tonic::Request;

use crate::utils::block_on;

/// An implementation of [`crate::ProverClient`] that can generate proofs via the monerochan network API.
pub struct NetworkProver {
    pub(crate) endpoint: String,
    pub(crate) prover: CpuProver,
    pub(crate) tee_signers: Vec<Address>,
    pub(crate) network_mode: NetworkMode,
}

impl NetworkProver {
    /// Creates a new [`NetworkProver`] that connects to the monerochan network API.
    ///
    /// # Details
    /// * `network_mode`: The network mode (for compatibility, but all requests go through network API).
    /// * `rpc_url`: The URL of the monerochan network API endpoint.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{network::NetworkMode, NetworkProver};
    ///
    /// let prover = NetworkProver::new(NetworkMode::Reserved, "https://rpc.production.monero-chan.org");
    /// ```
    #[must_use]
    pub fn new(
        network_mode: NetworkMode,
        rpc_url: String,
    ) -> Self {
        // Install default CryptoProvider if not already installed.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let prover = CpuProver::new();
        Self { 
            endpoint: rpc_url, 
            prover, 
            tee_signers: vec![], 
            network_mode,
        }
    }

    /// Sets the list of TEE signers, used for verifying TEE proofs.
    #[must_use]
    pub fn with_tee_signers(mut self, tee_signers: Vec<Address>) -> Self {
        self.tee_signers = tee_signers;
        self
    }

    /// Gets the network mode of this prover.
    pub fn network_mode(&self) -> NetworkMode {
        self.network_mode
    }

    /// Gets the default fulfillment strategy for this prover's network mode.
    /// 
    /// The network API only supports Reserved or Hosted fulfillment strategies.
    pub fn default_fulfillment_strategy(&self) -> FulfillmentStrategy {
        FulfillmentStrategy::Reserved
    }

    /// Creates a new [`CpuExecuteBuilder`] for simulating the execution of a program on the CPU.
    ///
    /// # Details
    /// Note that this does not use the network in any capacity. The method is provided for
    /// convenience.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (public_values, execution_report) = client.execute(elf, &stdin).run().unwrap();
    /// ```
    pub fn execute<'a>(&'a self, elf: &'a [u8], stdin: &MONEROCHANStdin) -> CpuExecuteBuilder<'a> {
        CpuExecuteBuilder {
            prover: self.prover.inner(),
            elf,
            stdin: stdin.clone(),
            context_builder: MONEROCHANContextBuilder::default(),
        }
    }

    /// A request to generate a proof for a given proving key and input.
    ///
    /// # Details
    /// * `pk`: The proving key to use for the proof.
    /// * `stdin`: The input to use for the proof.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().network().build();
    /// let (pk, vk) = client.setup(elf);
    /// let proof = client.prove(&pk, &stdin).run();
    /// ```
    pub fn prove<'a>(
        &'a self,
        pk: &'a MONEROCHANProvingKey,
        stdin: &'a MONEROCHANStdin,
    ) -> NetworkProveBuilder<'a> {
        NetworkProveBuilder {
            prover: self,
            mode: MONEROCHANProofMode::Core,
            pk,
            stdin: stdin.clone(),
            timeout: None,
            strategy: self.default_fulfillment_strategy(),
            skip_simulation: false,
            cycle_limit: None,
            gas_limit: None,
            tee_2fa: false,
            min_auction_period: 0,
            whitelist: None,
            auctioneer: None,
            executor: None,
            verifier: None,
            treasury: None,
            max_price_per_pgu: None,
            auction_timeout: None,
        }
    }

    /// Registers a program on the network and returns the verifying key hash.
    ///
    /// # Details
    /// * `vk`: The verifying key to register.
    /// * `elf`: The ELF bytes of the program.
    ///
    /// Note: With the network API, program registration happens automatically when you submit
    /// a proof request. This method returns the vk hash (program_id) that will be used.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let client = ProverClient::builder().network().build();
    /// let (pk, vk) = client.setup(elf);
    ///
    /// let vk_hash = client.register_program(&vk, elf).await.unwrap();
    /// ```
    pub async fn register_program(&self, vk: &MONEROCHANVerifyingKey, _elf: &[u8]) -> Result<B256> {
        // With NetworkApi, program registration happens automatically when submitting proofs.
        // Just return the vk hash (program_id) that will be used.
        Ok(B256::from_slice(&vk.bytes32_raw()))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn prove_impl(
        &self,
        pk: &MONEROCHANProvingKey,
        stdin: &MONEROCHANStdin,
        mode: MONEROCHANProofMode,
        strategy: FulfillmentStrategy,
        timeout: Option<Duration>,
        skip_simulation: bool,
        cycle_limit: Option<u64>,
        gas_limit: Option<u64>,
        tee_2fa: bool,
        min_auction_period: u64,
        whitelist: Option<Vec<Address>>,
        auctioneer: Option<Address>,
        executor: Option<Address>,
        verifier: Option<Address>,
        treasury: Option<Address>,
        max_price_per_pgu: Option<u64>,
        auction_timeout: Option<Duration>,
    ) -> Result<MONEROCHANProofWithPublicValues> {
        if tee_2fa {
            return Err(anyhow!(
                "TEE 2FA is not supported when using the network API backend"
            ));
        }

        // Network API only supports Reserved/Hosted mode, not Auction
        // Reject auction strategy early with clear error message
        if strategy == FulfillmentStrategy::Auction {
            return Err(anyhow!(
                "Auction mode is disabled. \
                The network API only supports Reserved or Hosted fulfillment strategies. \
                Please use FulfillmentStrategy::Reserved or FulfillmentStrategy::Hosted instead."
            ));
        }

        // Reject auction-specific parameters
        if min_auction_period != 0 {
            return Err(anyhow!(
                "min_auction_period is not supported. \
                Auction mode is disabled - please set min_auction_period to 0 or use Reserved/Hosted strategy."
            ));
        }

        if whitelist.is_some() && !whitelist.as_ref().unwrap().is_empty() {
            return Err(anyhow!(
                "whitelist is not supported. \
                Auction mode is disabled - please remove whitelist or use Reserved/Hosted strategy."
            ));
        }

        if auctioneer.is_some() {
            return Err(anyhow!(
                "auctioneer is not supported. \
                Auction mode is disabled - please remove auctioneer or use Reserved/Hosted strategy."
            ));
        }

        if executor.is_some() {
            return Err(anyhow!(
                "executor is not supported. \
                Auction mode is disabled - please remove executor or use Reserved/Hosted strategy."
            ));
        }

        if verifier.is_some() {
            return Err(anyhow!(
                "verifier is not supported. \
                Auction mode is disabled - please remove verifier or use Reserved/Hosted strategy."
            ));
        }

        if treasury.is_some() {
            return Err(anyhow!(
                "treasury is not supported. \
                Auction mode is disabled - please remove treasury or use Reserved/Hosted strategy."
            ));
        }

        if max_price_per_pgu.is_some() {
            return Err(anyhow!(
                "max_price_per_pgu is not supported. \
                Auction mode is disabled - please remove max_price_per_pgu or use Reserved/Hosted strategy."
            ));
        }

        if auction_timeout.is_some() {
            return Err(anyhow!(
                "auction_timeout is not supported. \
                Auction mode is disabled - please remove auction_timeout or use Reserved/Hosted strategy."
            ));
        }

        // Use strategy as-is (should be Reserved or Hosted at this point)
        let api_strategy = strategy;
        let api_min_auction_period = 0;

        self
            .prove_via_api(
                pk,
                stdin,
                mode,
                api_strategy,
                timeout,
                skip_simulation,
                cycle_limit,
                gas_limit,
                api_min_auction_period,
                whitelist,
                auctioneer,
                executor,
                verifier,
                treasury,
                max_price_per_pgu,
                auction_timeout,
            )
            .await
    }

    async fn client(&self) -> Result<NetworkClient<Channel>> {
        // Use grpc::configure_endpoint which handles TLS automatically for HTTPS URLs
        let channel = super::grpc::configure_endpoint(&self.endpoint)?
            .connect()
            .await
            .with_context(|| format!("failed to connect to network endpoint: {}", self.endpoint))?;
        Ok(NetworkClient::new(channel))
    }

    /// Submit a proof request to the network.
    pub(crate) async fn request_proof_impl(
        &self,
        pk: &MONEROCHANProvingKey,
        stdin: &MONEROCHANStdin,
        mode: MONEROCHANProofMode,
        strategy: FulfillmentStrategy,
        timeout: Option<Duration>,
        skip_simulation: bool,
        cycle_limit: Option<u64>,
        gas_limit: Option<u64>,
        min_auction_period: u64,
        whitelist: Option<Vec<Address>>,
        auctioneer: Option<Address>,
        executor: Option<Address>,
        verifier: Option<Address>,
        treasury: Option<Address>,
        max_price_per_pgu: Option<u64>,
    ) -> Result<B256> {
        let stdin_bytes =
            bincode::serialize(stdin).context("failed to serialize stdin for API request")?;

        let whitelist_bytes =
            whitelist.unwrap_or_default().into_iter().map(|address| address.to_vec()).collect();

        // Check for Solana private key from env var and create client auth if so
        #[cfg(feature = "network")]
        let (client_address, client_auth) = {
            // Check MONEROCHAN_NETWORK_PRIVATE_KEY first, then fall back to BASE_PRIVATE_KEY
            let private_key_str = std::env::var("MONEROCHAN_NETWORK_PRIVATE_KEY")
                .ok()
                .or_else(|| std::env::var("BASE_PRIVATE_KEY").ok());

            let private_key_bytes = private_key_str.and_then(|solana_key_str| {
                // Parse private key (support both hex and base58)
                if solana_key_str.starts_with("0x") {
                    hex::decode(&solana_key_str[2..]).ok()
                } else {
                    bs58::decode(&solana_key_str).into_vec().ok()
                        .or_else(|| hex::decode(&solana_key_str).ok())
                }
            });
            
            if let Some(key_bytes) = private_key_bytes {
                // Create client auth
                let (job_id, nonce, timestamp, signature, addr) = 
                    crate::network::solana_client_auth::create_client_auth(&key_bytes)?;
                
                let auth = Some(ClientAuth {
                    job_id,
                    nonce,
                    timestamp,
                    signature,
                });
                
                (Some(addr), auth)
            } else {
                (None, None)
            }
        };
        
        #[cfg(not(feature = "network"))]
        let (client_address, client_auth) = (None, None);

        let request = RequestProofRequest {
            program_id: format!("0x{}", hex::encode(pk.vk.bytes32())),
            elf: pk.elf.clone(),
            stdin: stdin_bytes,
            proof_mode: network_api_proof_mode(mode) as i32,
            strategy: network_api_strategy(strategy) as i32,
            timeout_secs: timeout.map(|value| value.as_secs()),
            skip_simulation,
            cycle_limit,
            gas_limit,
            min_auction_period,
            whitelist: whitelist_bytes,
            auctioneer: address_vec(auctioneer),
            executor: address_vec(executor),
            verifier: address_vec(verifier),
            treasury: address_vec(treasury),
            max_price_per_pgu,
            auction_timeout_secs: None,
            client_address,
            client_auth,
        };

        let request_id = self.request_proof(request).await?;
        Ok(B256::from_str(&request_id).context("invalid request_id format")?)
    }

    async fn request_proof(&self, request: RequestProofRequest) -> Result<String> {
        let mut client = self.client().await?;
        let response =
            client.request_proof(Request::new(request)).await.context("network request failed")?;
        let inner = response.into_inner();
        
        // Log explorer URL if provided
        if !inner.explorer_url.is_empty() {
            tracing::info!(request_id = %inner.request_id, explorer_url = %inner.explorer_url, "submitted proof request to network");
            eprintln!("Proof submitted. Check its progress in explorer: {}", inner.explorer_url);
        } else {
            tracing::info!(request_id = %inner.request_id, "submitted proof request to network");
            eprintln!("Proof submitted");
        }
        
        Ok(inner.request_id)
    }

    async fn fetch_status(&self, request_id: &str) -> Result<GetProofStatusResponse> {
        let mut client = self.client().await?;
        let response = client
            .get_proof_status(Request::new(GetProofStatusRequest {
                request_id: request_id.to_string(),
            }))
            .await
            .context("network status request failed")?;
        Ok(response.into_inner())
    }

    /// Wait until the network returns a completed proof or an error.
    ///
    /// # Details
    /// This method polls the network until the proof request completes or times out.
    /// The `request_id` should be obtained from a previous `request_async()` call.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{network::NetworkMode, Prover, ProverClient, MONEROCHANStdin};
    /// use alloy_primitives::B256;
    ///
    /// # tokio_test::block_on(async {
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().network_for(NetworkMode::Reserved).build();
    /// let (pk, vk) = client.setup(elf);
    /// let request_id = client.prove(&pk, &stdin).request_async().await.unwrap();
    /// let proof = client.wait_proof(request_id, None, None).await.unwrap();
    /// # });
    /// ```
    pub async fn wait_proof(
        &self,
        request_id: B256,
        timeout: Option<Duration>,
        auction_timeout: Option<Duration>,
    ) -> Result<MONEROCHANProofWithPublicValues> {
        let request_id_str = format!("0x{}", hex::encode(request_id.as_slice()));
        self.wait_for_proof(&request_id_str, timeout, auction_timeout).await
    }

    /// Wait until the network returns a completed proof or an error.
    async fn wait_for_proof(
        &self,
        request_id: &str,
        timeout: Option<Duration>,
        auction_timeout: Option<Duration>,
    ) -> Result<MONEROCHANProofWithPublicValues> {
        let start = Instant::now();
        let mut pending_start: Option<Instant> = None;

        loop {
            if let Some(timeout) = timeout {
                if start.elapsed() > timeout {
                    return Err(Error::RequestTimedOut {
                        request_id: request_id.as_bytes().to_vec(),
                    }
                    .into());
                }
            }

            let status = self.fetch_status(request_id).await?;
            match JobStatus::try_from(status.status).ok() {
                Some(JobStatus::Succeeded) => {
                    if status.proof.is_empty() {
                        return Err(anyhow!("network reported success but no proof was returned"));
                    }
                    // Network returns proof.bytes() from SP1 SDK, which is serialized ProofFromNetwork
                    let proof_from_network: ProofFromNetwork =
                        bincode::deserialize(&status.proof).context("failed to decode proof")?;
                    return Ok(proof_from_network.into());
                }
                Some(JobStatus::Failed) => {
                    let err = if status.error_message.is_empty() {
                        "network job failed".to_string()
                    } else {
                        status.error_message
                    };
                    return Err(anyhow!(err));
                }
                Some(JobStatus::Running) => {
                    pending_start = None;
                }
                Some(JobStatus::Pending) | Some(JobStatus::Unspecified) => {
                    if pending_start.is_none() {
                        pending_start = Some(Instant::now());
                    }
                    if let (Some(start_time), Some(limit)) = (pending_start, auction_timeout) {
                        if start_time.elapsed() > limit {
                            return Err(Error::RequestAuctionTimedOut {
                                request_id: request_id.as_bytes().to_vec(),
                            }
                            .into());
                        }
                    }
                }
                None => return Err(anyhow!("unknown network job status")),
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn prove_via_api(
        &self,
        pk: &MONEROCHANProvingKey,
        stdin: &MONEROCHANStdin,
        mode: MONEROCHANProofMode,
        strategy: FulfillmentStrategy,
        timeout: Option<Duration>,
        skip_simulation: bool,
        cycle_limit: Option<u64>,
        gas_limit: Option<u64>,
        min_auction_period: u64,
        whitelist: Option<Vec<Address>>,
        auctioneer: Option<Address>,
        executor: Option<Address>,
        verifier: Option<Address>,
        treasury: Option<Address>,
        max_price_per_pgu: Option<u64>,
        auction_timeout: Option<Duration>,
    ) -> Result<MONEROCHANProofWithPublicValues> {
        let stdin_bytes =
            bincode::serialize(stdin).context("failed to serialize stdin for API request")?;

        let whitelist_bytes =
            whitelist.unwrap_or_default().into_iter().map(|address| address.to_vec()).collect();

        // Check for Solana private key from env var and create client auth if so
        #[cfg(feature = "network")]
        let (client_address, client_auth) = {
            // Check MONEROCHAN_NETWORK_PRIVATE_KEY first, then fall back to BASE_PRIVATE_KEY
            let private_key_str = std::env::var("MONEROCHAN_NETWORK_PRIVATE_KEY")
                .ok()
                .or_else(|| std::env::var("BASE_PRIVATE_KEY").ok());

            let private_key_bytes = private_key_str.and_then(|solana_key_str| {
                // Parse private key (support both hex and base58)
                if solana_key_str.starts_with("0x") {
                    hex::decode(&solana_key_str[2..]).ok()
                } else {
                    bs58::decode(&solana_key_str).into_vec().ok()
                        .or_else(|| hex::decode(&solana_key_str).ok())
                }
            });
            
            if let Some(key_bytes) = private_key_bytes {
                // Create client auth
                let (job_id, nonce, timestamp, signature, addr) = 
                    crate::network::solana_client_auth::create_client_auth(&key_bytes)?;
                
                let auth = Some(ClientAuth {
                    job_id,
                    nonce,
                    timestamp,
                    signature,
                });
                
                (Some(addr), auth)
            } else {
                (None, None)
            }
        };
        
        #[cfg(not(feature = "network"))]
        let (client_address, client_auth) = (None, None);

        let request = RequestProofRequest {
            program_id: format!("0x{}", hex::encode(pk.vk.bytes32())),
            elf: pk.elf.clone(),
            stdin: stdin_bytes,
            proof_mode: network_api_proof_mode(mode) as i32,
            strategy: network_api_strategy(strategy) as i32,
            timeout_secs: timeout.map(|value| value.as_secs()),
            skip_simulation,
            cycle_limit,
            gas_limit,
            min_auction_period,
            whitelist: whitelist_bytes,
            auctioneer: address_vec(auctioneer),
            executor: address_vec(executor),
            verifier: address_vec(verifier),
            treasury: address_vec(treasury),
            max_price_per_pgu,
            auction_timeout_secs: auction_timeout.map(|value| value.as_secs()),
            client_address,
            client_auth,
        };

        let request_id = self.request_proof(request).await?;
        // Explorer URL is already logged by request_proof()

        self.wait_for_proof(&request_id, timeout, auction_timeout).await
    }

    // /// The cycle limit and gas limit are determined according to the following priority:
    // ///
    // /// 1. If either of the limits are explicitly set by the requester, use the specified value.
    // /// 2. If simulation is enabled, calculate the limits by simulating the execution of the
    // ///    program. This is the default behavior.
    // /// 3. Otherwise, use the default limits ([`MAINNET_DEFAULT_CYCLE_LIMIT`] or
    // ///    [`RESERVED_DEFAULT_CYCLE_LIMIT`] and [`DEFAULT_GAS_LIMIT`]).
    // #[allow(dead_code)]
    // fn get_execution_limits(
    //     &self,
    //     cycle_limit: Option<u64>,
    //     gas_limit: Option<u64>,
    //     elf: &[u8],
    //     stdin: &MONEROCHANStdin,
    //     skip_simulation: bool,
    // ) -> Result<(u64, u64, Option<Vec<u8>>)> {
    //     let cycle_limit_value = if let Some(cycles) = cycle_limit {
    //         cycles
    //     } else if skip_simulation {
    //         super::utils::get_default_cycle_limit_for_mode(self.network_mode)
    //     } else {
    //         // Will be calculated through simulation.
    //         0
    //     };
    //
    //     let gas_limit_value = if let Some(gas) = gas_limit {
    //         gas
    //     } else if skip_simulation {
    //         DEFAULT_GAS_LIMIT
    //     } else {
    //         // Will be calculated through simulation.
    //         0
    //     };
    //
    //     // If both limits were explicitly provided or skip_simulation is true, return immediately.
    //     if (cycle_limit.is_some() && gas_limit.is_some()) || skip_simulation {
    //         return Ok((cycle_limit_value, gas_limit_value, None));
    //     }
    //
    //     // One of the limits were not provided and simulation is not skipped, so simulate to get
    //     // one. or both limits.
    //     let execute_result = self
    //         .prover
    //         .inner()
    //         .execute(elf, stdin, MONEROCHANContext::builder().calculate_gas(true).build())
    //         .map_err(|_| Error::SimulationFailed)?;
    //
    //     let (_, committed_value_digest, report) = execute_result;
    //
    //     // Use simulated values for the ones that are not explicitly provided.
    //     let final_cycle_limit = if cycle_limit.is_none() {
    //         report.total_instruction_count()
    //     } else {
    //         cycle_limit_value
    //     };
    //     let final_gas_limit = if gas_limit.is_none() {
    //         report.gas.unwrap_or(DEFAULT_GAS_LIMIT)
    //     } else {
    //         gas_limit_value
    //     };
    //
    //     let public_values_hash = Some(committed_value_digest.to_vec());
    //
    //     Ok((final_cycle_limit, final_gas_limit, public_values_hash))
    // }

}

impl Prover<CpuProverComponents> for NetworkProver {
    fn setup(&self, elf: &[u8]) -> (MONEROCHANProvingKey, MONEROCHANVerifyingKey) {
        self.prover.setup(elf)
    }

    fn inner(&self) -> &MONEROCHANProver {
        self.prover.inner()
    }

    fn prove(
        &self,
        pk: &MONEROCHANProvingKey,
        stdin: &MONEROCHANStdin,
        mode: MONEROCHANProofMode,
    ) -> Result<MONEROCHANProofWithPublicValues> {
        block_on(self.prove_impl(
            pk,
            stdin,
            mode,
            self.default_fulfillment_strategy(),
            None,
            false,
            None,
            None,
            false,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ))
    }

    fn verify(
        &self,
        bundle: &MONEROCHANProofWithPublicValues,
        vkey: &MONEROCHANVerifyingKey,
    ) -> Result<(), crate::MONEROCHANVerificationError> {
        if let Some(tee_proof) = &bundle.tee_proof {
            if self.tee_signers.is_empty() {
                return Err(crate::MONEROCHANVerificationError::Other(anyhow::anyhow!(
                    "TEE integrity proof verification is enabled, but no TEE signers are provided"
                )));
            }

            let mut bytes = Vec::new();

            // Push the version hash.
            let version_hash = alloy_primitives::keccak256(
                crate::network::tee::MONEROCHAN_TEE_VERSION.to_le_bytes(),
            );
            bytes.extend_from_slice(version_hash.as_ref());

            // Push the vkey.
            bytes.extend_from_slice(&vkey.bytes32_raw());

            // Push the public values hash.
            let public_values_hash = alloy_primitives::keccak256(&bundle.public_values);
            bytes.extend_from_slice(public_values_hash.as_ref());

            // Compute the message digest.
            let message_digest = alloy_primitives::keccak256(&bytes);

            // Parse the signature.
            let signature = k256::ecdsa::Signature::from_bytes(tee_proof[5..69].into())
                .expect("Invalid signature");
            // The recovery id is the last byte of the signature minus 27.
            let recovery_id =
                k256::ecdsa::RecoveryId::from_byte(tee_proof[4] - 27).expect("Invalid recovery id");

            // Recover the signer.
            let signer = k256::ecdsa::VerifyingKey::recover_from_prehash(
                message_digest.as_ref(),
                &signature,
                recovery_id,
            )
            .unwrap();
            let address = alloy_primitives::Address::from_public_key(&signer);

            // Verify the proof.
            if self.tee_signers.contains(&address) {
                verify_proof(self.prover.inner(), self.version(), bundle, vkey)
            } else {
                Err(crate::MONEROCHANVerificationError::Other(anyhow::anyhow!(
                    "Invalid TEE proof, signed by unknown address {}",
                    address
                )))
            }
        } else {
            verify_proof(self.prover.inner(), self.version(), bundle, vkey)
        }
    }
}

fn network_api_proof_mode(mode: MONEROCHANProofMode) -> NetworkApiProofMode {
    match mode {
        MONEROCHANProofMode::Compressed => NetworkApiProofMode::Compressed,
        MONEROCHANProofMode::Plonk => NetworkApiProofMode::Plonk,
        MONEROCHANProofMode::Groth16 => NetworkApiProofMode::Groth16,
        MONEROCHANProofMode::Core => NetworkApiProofMode::Core,
    }
}

fn network_api_strategy(strategy: FulfillmentStrategy) -> NetworkApiFulfillmentStrategy {
    match strategy {
        FulfillmentStrategy::Hosted => NetworkApiFulfillmentStrategy::Hosted,
        FulfillmentStrategy::Auction => NetworkApiFulfillmentStrategy::Auction,
        FulfillmentStrategy::Reserved => NetworkApiFulfillmentStrategy::Hosted, // Network API maps Reserved to Hosted
        FulfillmentStrategy::UnspecifiedFulfillmentStrategy => NetworkApiFulfillmentStrategy::Unspecified, // Maps to Unspecified in network API proto
    }
}

fn address_vec(address: Option<Address>) -> Vec<u8> {
    address.map(|addr| addr.as_slice().to_vec()).unwrap_or_default()
}

