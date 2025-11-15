//! # CPU Proving
//!
//! This module provides a builder for proving a program on the CPU.

use anyhow::Result;
use monerochan_core_executor::{IoWriter, MONEROCHANContextBuilder};
use monerochan_core_machine::io::MONEROCHANStdin;
use monerochan_prover::MONEROCHANProvingKey;
use monerochan_stark::{MONEROCHANCoreOpts, MONEROCHANProverOpts};

use super::CpuProver;
use crate::{MONEROCHANProofMode, MONEROCHANProofWithPublicValues};

/// A builder for proving a program on the CPU.
///
/// This builder provides a typed interface for configuring the MONEROCHAN RISC-V prover. The builder is
/// used for only the [`crate::cpu::CpuProver`] client type.
pub struct CpuProveBuilder<'a> {
    pub(crate) prover: &'a CpuProver,
    pub(crate) mode: MONEROCHANProofMode,
    pub(crate) context_builder: MONEROCHANContextBuilder<'a>,
    pub(crate) pk: &'a MONEROCHANProvingKey,
    pub(crate) stdin: MONEROCHANStdin,
    pub(crate) core_opts: MONEROCHANCoreOpts,
    pub(crate) recursion_opts: MONEROCHANCoreOpts,
    pub(crate) mock: bool,
}

impl<'a> CpuProveBuilder<'a> {
    /// Set the proof kind to [`MONEROCHANProofKind::Core`] mode.
    ///
    /// # Details
    /// This is the default mode for the prover. The proofs grow linearly in size with the number
    /// of cycles.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).core().run();
    /// ```
    #[must_use]
    pub fn core(mut self) -> Self {
        self.mode = MONEROCHANProofMode::Core;
        self
    }

    /// Set the proof kind to [`MONEROCHANProofKind::Compressed`] mode.
    ///
    /// # Details
    /// This mode produces a proof that is of constant size, regardless of the number of cycles. It
    /// takes longer to prove than [`MONEROCHANProofKind::Core`] due to the need to recursively aggregate
    /// proofs into a single proof.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).compressed().run();
    /// ```
    #[must_use]
    pub fn compressed(mut self) -> Self {
        self.mode = MONEROCHANProofMode::Compressed;
        self
    }

    /// Set the proof mode to [`MONEROCHANProofKind::Plonk`] mode.
    ///
    /// # Details
    /// This mode produces a const size PLONK proof that can be verified on chain for roughly ~300k
    /// gas. This mode is useful for producing a maximally small proof that can be verified on
    /// chain. For more efficient SNARK wrapping, you can use the [`MONEROCHANProofKind::Groth16`] mode but
    /// this mode is more .
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).plonk().run();
    /// ```
    #[must_use]
    pub fn plonk(mut self) -> Self {
        self.mode = MONEROCHANProofMode::Plonk;
        self
    }

    /// Set the proof mode to [`MONEROCHANProofKind::Groth16`] mode.
    ///
    /// # Details
    /// This mode produces a Groth16 proof that can be verified on chain for roughly ~100k gas. This
    /// mode is useful for producing a proof that can be verified on chain with minimal gas.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).groth16().run();
    /// ```
    #[must_use]
    pub fn groth16(mut self) -> Self {
        self.mode = MONEROCHANProofMode::Groth16;
        self
    }

    /// Set the proof mode to the given [`MONEROCHANProofKind`].
    ///
    /// # Details
    /// This method is useful for setting the proof mode to a custom mode.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANProofMode, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).mode(MONEROCHANProofMode::Groth16).run();
    /// ```
    #[must_use]
    pub fn mode(mut self, mode: MONEROCHANProofMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the shard size for proving.
    ///
    /// # Details
    /// The value should be 2^16, 2^17, ..., 2^22. You must be careful to set this value
    /// correctly, as it will affect the memory usage of the prover and the recursion/verification
    /// complexity. By default, the value is set to some predefined values that are optimized for
    /// performance based on the available amount of RAM on the system.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).shard_size(1 << 16).run();
    /// ```
    #[must_use]
    pub fn shard_size(mut self, value: usize) -> Self {
        assert!(value.is_power_of_two(), "shard size must be a power of 2");
        self.core_opts.shard_size = value;
        self
    }

    /// Set the shard batch size for proving.
    ///
    /// # Details
    /// This is the number of shards that are processed in a single batch in the prover. You should
    /// probably not change this value unless you know what you are doing.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).shard_batch_size(4).run();
    /// ```
    #[must_use]
    pub fn shard_batch_size(mut self, value: usize) -> Self {
        self.core_opts.shard_batch_size = value;
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    ///
    /// # Details
    /// If the cycle limit is exceeded, execution will return
    /// [`monerochan_core_executor::ExecutionError::ExceededCycleLimit`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).cycle_limit(1000000).run();
    /// ```
    #[must_use]
    pub fn cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.context_builder.max_cycles(cycle_limit);
        self
    }

    /// Whether to enable deferred proof verification in the executor.
    ///
    /// # Arguments
    /// * `value` - Whether to enable deferred proof verification in the executor.
    ///
    /// # Details
    /// Default: `true`. If set to `false`, the executor will skip deferred proof verification.
    /// This is useful for reducing the execution time of the program and optimistically assuming
    /// that the deferred proofs are correct. Can also be used for mock proof setups that require
    /// verifying mock compressed proofs.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).deferred_proof_verification(false).run();
    /// ```
    #[must_use]
    pub fn deferred_proof_verification(mut self, value: bool) -> Self {
        self.context_builder.set_deferred_proof_verification(value);
        self
    }

    /// Override the default stdout of the guest program.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let mut stdout = Vec::new();
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// client.execute(elf, &stdin).stdout(&mut stdout).run();
    /// ```
    #[must_use]
    pub fn stdout<W: IoWriter>(mut self, writer: &'a mut W) -> Self {
        self.context_builder.stdout(writer);
        self
    }

    /// Override the default stdout of the guest program.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let mut stderr = Vec::new();
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// client.execute(elf, &stdin).stderr(&mut stderr).run();
    /// ```````
    #[must_use]
    pub fn stderr<W: IoWriter>(mut self, writer: &'a mut W) -> Self {
        self.context_builder.stderr(writer);
        self
    }

    /// Run the prover with the built arguments.
    ///
    /// # Details
    /// This method will run the prover with the built arguments. If the prover fails to run, the
    /// method will return an error.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (pk, vk) = client.setup(elf);
    /// let proof = client.prove(&pk, &stdin).run().unwrap();
    /// ```
    pub fn run(self) -> Result<MONEROCHANProofWithPublicValues> {
        // Get the arguments.
        let Self { prover, mode, pk, stdin, mut context_builder, core_opts, recursion_opts, mock } =
            self;
        let opts = MONEROCHANProverOpts { core_opts, recursion_opts };
        let context = context_builder.build();

        // Dump the program and stdin to files for debugging if `MONEROCHAN_DUMP` is set.
        crate::utils::monerochan_dump(&pk.elf, &stdin);

        // Run the prover.
        if mock {
            prover.mock_prove_impl(pk, &stdin, context, mode)
        } else {
            prover.prove_impl(pk, &stdin, opts, context, mode)
        }
    }
}
