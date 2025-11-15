//! # Env Proving
//!
//! This module provides a builder for proving a program.

use anyhow::Result;
use monerochan_core_machine::io::MONEROCHANStdin;
use monerochan_prover::{components::CpuProverComponents, MONEROCHANProvingKey};

use crate::{Prover, MONEROCHANProofMode, MONEROCHANProofWithPublicValues};

/// Builder to prepare and configure proving execution of a program on an input.
/// May be run with [`Self::run`].
pub struct EnvProveBuilder<'a> {
    pub(crate) prover: &'a dyn Prover<CpuProverComponents>,
    pub(crate) mode: MONEROCHANProofMode,
    pub(crate) pk: &'a MONEROCHANProvingKey,
    pub(crate) stdin: MONEROCHANStdin,
}

impl EnvProveBuilder<'_> {
    /// Set the proof kind to [`MONEROCHANProofMode::Core`] mode.
    ///
    /// # Details
    /// This is the default mode for the prover. The proofs grow linearly in size with the number
    /// of cycles.
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
    pub fn core(mut self) -> Self {
        self.mode = MONEROCHANProofMode::Core;
        self
    }

    /// Set the proof kind to [`MONEROCHANProofMode::Compressed`] mode.
    ///
    /// # Details
    /// This mode produces a proof that is of constant size, regardless of the number of cycles. It
    /// takes longer to prove than [`MONEROCHANProofMode::Core`] due to the need to recursively aggregate
    /// proofs into a single proof.
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
    /// let builder = client.prove(&pk, &stdin).compressed().run();
    /// ```
    #[must_use]
    pub fn compressed(mut self) -> Self {
        self.mode = MONEROCHANProofMode::Compressed;
        self
    }

    /// Set the proof mode to [`MONEROCHANProofMode::Plonk`] mode.
    ///
    /// # Details
    /// This mode produces a const size PLONK proof that can be verified on chain for roughly ~300k
    /// gas. This mode is useful for producing a maximally small proof that can be verified on
    /// chain. For more efficient SNARK wrapping, you can use the [`MONEROCHANProofMode::Groth16`] mode but
    /// this mode is more .
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
    /// let builder = client.prove(&pk, &stdin).plonk().run();
    /// ```
    #[must_use]
    pub fn plonk(mut self) -> Self {
        self.mode = MONEROCHANProofMode::Plonk;
        self
    }

    /// Set the proof mode to [`MONEROCHANProofMode::Groth16`] mode.
    ///
    /// # Details
    /// This mode produces a Groth16 proof that can be verified on chain for roughly ~100k gas. This
    /// mode is useful for producing a proof that can be verified on chain with minimal gas.
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
    /// let builder = client.prove(&pk, &stdin).groth16().run();
    /// ```
    #[must_use]
    pub fn groth16(mut self) -> Self {
        self.mode = MONEROCHANProofMode::Groth16;
        self
    }

    /// Set the proof mode to the given [`MONEROCHANProofMode`].
    ///
    /// # Details
    /// This method is useful for setting the proof mode to a custom mode.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{Prover, ProverClient, MONEROCHANProofMode, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::from_env();
    /// let (pk, vk) = client.setup(elf);
    /// let builder = client.prove(&pk, &stdin).mode(MONEROCHANProofMode::Groth16).run();
    /// ```
    #[must_use]
    pub fn mode(mut self, mode: MONEROCHANProofMode) -> Self {
        self.mode = mode;
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
    /// use monerochan::{Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::from_env();
    /// let (pk, vk) = client.setup(elf);
    /// let proof = client.prove(&pk, &stdin).run().unwrap();
    /// ```
    pub fn run(self) -> Result<MONEROCHANProofWithPublicValues> {
        let Self { prover, mode: kind, pk, stdin } = self;

        // Dump the program and stdin to files for debugging if `MONEROCHAN_DUMP` is set.
        crate::utils::monerochan_dump(&pk.elf, &stdin);

        prover.prove(pk, &stdin, kind)
    }
}
