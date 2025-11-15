//! # MONEROCHAN Environment Prover
//!
//! A prover that can execute programs and generate proofs with a different implementation based on
//! the value of certain environment variables.

pub mod prove;

use std::env;

use anyhow::Result;
use prove::EnvProveBuilder;
use monerochan_core_executor::MONEROCHANContextBuilder;
use monerochan_core_machine::io::MONEROCHANStdin;
use monerochan_cuda::MoongateServer;
use monerochan_prover::{components::CpuProverComponents, MONEROCHANProver, MONEROCHANProvingKey, MONEROCHANVerifyingKey};

use super::{Prover, MONEROCHANVerificationError};
#[cfg(feature = "network")]
use crate::network::builder::NetworkProverBuilder;
use crate::{
    cpu::{execute::CpuExecuteBuilder, CpuProver},
    cuda::CudaProver,
    utils::{check_release_build, setup_memory_usage_monitoring},
    MONEROCHANProofMode, MONEROCHANProofWithPublicValues,
};

/// A prover that can execute programs and generate proofs with a different implementation based on
/// the value of certain environment variables.
///
/// The environment variables are described in [`EnvProver::new`].
pub struct EnvProver {
    pub(crate) prover: Box<dyn Prover<CpuProverComponents>>,
}

impl EnvProver {
    /// Creates a new [`EnvProver`] with the given configuration.
    ///
    /// The following environment variables are used to configure the prover:
    /// - `MONEROCHAN_PROVER`: The type of prover to use. Must be one of `mock`, `local`, `cuda`, or
    ///   `network`.
    /// - `MONEROCHAN_NETWORK_PRIVATE_KEY`: The Solana private key (hex or base58) for client authentication when using network prover.
    /// - `NETWORK_RPC_URL`: The RPC URL to use for the network prover (defaults to monerochan production network).
    #[must_use]
    pub fn new() -> Self {
        let mode = if let Ok(mode) = env::var("MONEROCHAN_PROVER") {
            mode
        } else {
            tracing::warn!("MONEROCHAN_PROVER environment variable not set, defaulting to 'cpu'");
            "cpu".to_string()
        };

        let prover: Box<dyn Prover<CpuProverComponents>> = match mode.as_str() {
            "mock" => Box::new(CpuProver::mock()),
            "cpu" => {
                check_release_build();
                setup_memory_usage_monitoring();
                Box::new(CpuProver::new())
            },
            "cuda" => {
                check_release_build();
                setup_memory_usage_monitoring();
                Box::new(CudaProver::new(MONEROCHANProver::new(), MoongateServer::default()))
            }
            "network" => {
                #[cfg(not(feature = "network"))]
                panic!(
                    r#"The network prover requires the 'network' feature to be enabled.
                    Please enable it in your Cargo.toml with:
                    monerochan = {{ version = "...", features = ["network"] }}"#
                );

                #[cfg(feature = "network")]
                {
                    Box::new(NetworkProverBuilder::default().build())
                }
            }
            _ => panic!(
                "Invalid MONEROCHAN_PROVER value. Expected one of: mock, cpu, cuda, or network. Got: '{mode}'.\n\
                Please set the MONEROCHAN_PROVER environment variable to one of the supported values."
            ),
        };
        EnvProver { prover }
    }

    /// Creates a new [`CpuExecuteBuilder`] for simulating the execution of a program on the CPU.
    ///
    /// # Details
    /// The builder is used for both the [`crate::cpu::CpuProver`] and [`crate::CudaProver`] client
    /// types.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::from_env();
    /// let (public_values, execution_report) = client.execute(elf, &stdin).run().unwrap();
    /// ```
    #[must_use]
    pub fn execute<'a>(&'a self, elf: &'a [u8], stdin: &MONEROCHANStdin) -> CpuExecuteBuilder<'a> {
        CpuExecuteBuilder {
            prover: self.prover.inner(),
            elf,
            stdin: stdin.clone(),
            context_builder: MONEROCHANContextBuilder::default(),
        }
    }

    /// Creates a new [`EnvProveBuilder`] for proving a program on the CPU.
    ///
    /// # Details
    /// The builder is used for only the [`crate::cpu::CpuProver`] client type.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::from_env();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).core().run();
    /// ```
    #[must_use]
    pub fn prove<'a>(&'a self, pk: &'a MONEROCHANProvingKey, stdin: &'a MONEROCHANStdin) -> EnvProveBuilder<'a> {
        EnvProveBuilder {
            prover: self.prover.as_ref(),
            mode: MONEROCHANProofMode::Core,
            pk,
            stdin: stdin.clone(),
        }
    }

    /// Verifies that the given proof is valid and matches the given verification key produced by
    /// [`Self::setup`].
    ///
    /// ### Examples
    /// ```no_run
    /// use monerochan::{ProverClient, MONEROCHANStdin};
    ///
    /// let elf = test_artifacts::FIBONACCI_ELF;
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::from_env();
    /// let (pk, vk) = client.setup(elf);
    /// let proof = client.prove(&pk, &stdin).run().unwrap();
    /// client.verify(&proof, &vk).unwrap();
    /// ```
    pub fn verify(
        &self,
        proof: &MONEROCHANProofWithPublicValues,
        vk: &MONEROCHANVerifyingKey,
    ) -> Result<(), MONEROCHANVerificationError> {
        self.prover.verify(proof, vk)
    }

    /// Setup a program to be proven and verified by the MONEROCHAN RISC-V zkVM by computing the proving
    /// and verifying keys.
    #[must_use]
    pub fn setup(&self, elf: &[u8]) -> (MONEROCHANProvingKey, MONEROCHANVerifyingKey) {
        self.prover.setup(elf)
    }
}

impl Default for EnvProver {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover<CpuProverComponents> for EnvProver {
    fn inner(&self) -> &MONEROCHANProver<CpuProverComponents> {
        self.prover.inner()
    }

    fn setup(&self, elf: &[u8]) -> (MONEROCHANProvingKey, MONEROCHANVerifyingKey) {
        self.prover.setup(elf)
    }

    fn prove(
        &self,
        pk: &MONEROCHANProvingKey,
        stdin: &MONEROCHANStdin,
        mode: MONEROCHANProofMode,
    ) -> Result<MONEROCHANProofWithPublicValues> {
        self.prover.prove(pk, stdin, mode)
    }

    fn verify(
        &self,
        bundle: &MONEROCHANProofWithPublicValues,
        vkey: &MONEROCHANVerifyingKey,
    ) -> Result<(), MONEROCHANVerificationError> {
        self.prover.verify(bundle, vkey)
    }
}
