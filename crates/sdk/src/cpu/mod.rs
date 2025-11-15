//! # MONEROCHAN CPU Prover
//!
//! A prover that uses the CPU to execute and prove programs.

pub mod builder;
pub mod execute;
pub mod prove;

use anyhow::Result;
use execute::CpuExecuteBuilder;
use prove::CpuProveBuilder;
use monerochan_core_executor::{MONEROCHANContext, MONEROCHANContextBuilder};
use monerochan_core_machine::io::MONEROCHANStdin;
use monerochan_prover::{
    components::CpuProverComponents,
    verify::{verify_groth16_bn254_public_inputs, verify_plonk_bn254_public_inputs},
    Groth16Bn254Proof, PlonkBn254Proof, MONEROCHANCoreProofData, MONEROCHANProofWithMetadata, MONEROCHANProver,
};
use monerochan_stark::{MONEROCHANCoreOpts, MONEROCHANProverOpts};

use crate::{
    install::try_install_circuit_artifacts, prover::verify_proof, Prover, MONEROCHANProof, MONEROCHANProofMode,
    MONEROCHANProofWithPublicValues, MONEROCHANProvingKey, MONEROCHANVerificationError, MONEROCHANVerifyingKey,
};

/// A prover that uses the CPU to execute and prove programs.
pub struct CpuProver {
    pub(crate) prover: MONEROCHANProver<CpuProverComponents>,
    pub(crate) mock: bool,
}

impl CpuProver {
    /// Creates a new [`CpuProver`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new [`CpuProver`] in mock mode.
    #[must_use]
    pub fn mock() -> Self {
        Self { prover: MONEROCHANProver::new(), mock: true }
    }

    /// Creates a new [`CpuExecuteBuilder`] for simulating the execution of a program on the CPU.
    ///
    /// # Details
    /// The builder is used for both the [`crate::cpu::CpuProver`] and [`crate::CudaProver`] client
    /// types.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cpu().build();
    /// let (public_values, execution_report) = client.execute(elf, &stdin).run().unwrap();
    /// ```
    pub fn execute<'a>(&'a self, elf: &'a [u8], stdin: &MONEROCHANStdin) -> CpuExecuteBuilder<'a> {
        CpuExecuteBuilder {
            prover: &self.prover,
            elf,
            stdin: stdin.clone(),
            context_builder: MONEROCHANContextBuilder::default(),
        }
    }

    /// Creates a new [`CpuProveBuilder`] for proving a program on the CPU.
    ///
    /// # Details
    /// The builder is used for only the [`crate::cpu::CpuProver`] client type.
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
    pub fn prove<'a>(&'a self, pk: &'a MONEROCHANProvingKey, stdin: &MONEROCHANStdin) -> CpuProveBuilder<'a> {
        CpuProveBuilder {
            prover: self,
            mode: MONEROCHANProofMode::Core,
            pk,
            stdin: stdin.clone(),
            context_builder: MONEROCHANContextBuilder::default(),
            core_opts: MONEROCHANCoreOpts::default(),
            recursion_opts: MONEROCHANCoreOpts::recursion(),
            mock: self.mock,
        }
    }

    pub(crate) fn prove_impl<'a>(
        &'a self,
        pk: &MONEROCHANProvingKey,
        stdin: &MONEROCHANStdin,
        opts: MONEROCHANProverOpts,
        context: MONEROCHANContext<'a>,
        mode: MONEROCHANProofMode,
    ) -> Result<MONEROCHANProofWithPublicValues> {
        let program = self.prover.get_program(&pk.elf).unwrap();

        // If we're in mock mode, return a mock proof.
        if self.mock {
            return self.mock_prove_impl(pk, stdin, context, mode);
        }

        // Generate the core proof.
        let proof: MONEROCHANProofWithMetadata<MONEROCHANCoreProofData> =
            self.prover.prove_core(&pk.pk, program, stdin, opts, context)?;
        if mode == MONEROCHANProofMode::Core {
            return Ok(MONEROCHANProofWithPublicValues::new(
                MONEROCHANProof::Core(proof.proof.0),
                proof.public_values,
                self.version().to_string(),
            ));
        }

        // Generate the compressed proof.
        let deferred_proofs =
            stdin.proofs.iter().map(|(reduce_proof, _)| reduce_proof.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs, opts)?;
        if mode == MONEROCHANProofMode::Compressed {
            return Ok(MONEROCHANProofWithPublicValues::new(
                MONEROCHANProof::Compressed(Box::new(reduce_proof)),
                public_values,
                self.version().to_string(),
            ));
        }

        // Generate the shrink proof.
        let compress_proof = self.prover.shrink(reduce_proof, opts)?;

        // Generate the wrap proof.
        let outer_proof = self.prover.wrap_bn254(compress_proof, opts)?;

        // Generate the gnark proof.
        match mode {
            MONEROCHANProofMode::Groth16 => {
                let groth16_bn254_artifacts = if monerochan_prover::build::monerochan_dev_mode() {
                    monerochan_prover::build::try_build_groth16_bn254_artifacts_dev(
                        &outer_proof.vk,
                        &outer_proof.proof,
                    )
                } else {
                    try_install_circuit_artifacts("groth16")
                };

                let proof = self.prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
                Ok(MONEROCHANProofWithPublicValues::new(
                    MONEROCHANProof::Groth16(proof),
                    public_values,
                    self.version().to_string(),
                ))
            }
            MONEROCHANProofMode::Plonk => {
                let plonk_bn254_artifacts = if monerochan_prover::build::monerochan_dev_mode() {
                    monerochan_prover::build::try_build_plonk_bn254_artifacts_dev(
                        &outer_proof.vk,
                        &outer_proof.proof,
                    )
                } else {
                    try_install_circuit_artifacts("plonk")
                };
                let proof = self.prover.wrap_plonk_bn254(outer_proof, &plonk_bn254_artifacts);
                Ok(MONEROCHANProofWithPublicValues::new(
                    MONEROCHANProof::Plonk(proof),
                    public_values,
                    self.version().to_string(),
                ))
            }
            _ => unreachable!(),
        }
    }

    pub(crate) fn mock_prove_impl<'a>(
        &'a self,
        pk: &MONEROCHANProvingKey,
        stdin: &MONEROCHANStdin,
        context: MONEROCHANContext<'a>,
        mode: MONEROCHANProofMode,
    ) -> Result<MONEROCHANProofWithPublicValues> {
        let (public_values, _, _) = self.prover.execute(&pk.elf, stdin, context)?;
        Ok(MONEROCHANProofWithPublicValues::create_mock_proof(pk, public_values, mode, self.version()))
    }

    fn mock_verify(
        bundle: &MONEROCHANProofWithPublicValues,
        vkey: &MONEROCHANVerifyingKey,
    ) -> Result<(), MONEROCHANVerificationError> {
        match &bundle.proof {
            MONEROCHANProof::Plonk(PlonkBn254Proof { public_inputs, .. }) => {
                verify_plonk_bn254_public_inputs(vkey, &bundle.public_values, public_inputs)
                    .map_err(MONEROCHANVerificationError::Plonk)
            }
            MONEROCHANProof::Groth16(Groth16Bn254Proof { public_inputs, .. }) => {
                verify_groth16_bn254_public_inputs(vkey, &bundle.public_values, public_inputs)
                    .map_err(MONEROCHANVerificationError::Groth16)
            }
            _ => Ok(()),
        }
    }
}

impl Prover<CpuProverComponents> for CpuProver {
    fn setup(&self, elf: &[u8]) -> (MONEROCHANProvingKey, MONEROCHANVerifyingKey) {
        let (pk, _, _, vk) = self.prover.setup(elf);
        (pk, vk)
    }

    fn inner(&self) -> &MONEROCHANProver<CpuProverComponents> {
        &self.prover
    }

    fn prove(
        &self,
        pk: &MONEROCHANProvingKey,
        stdin: &MONEROCHANStdin,
        mode: MONEROCHANProofMode,
    ) -> Result<MONEROCHANProofWithPublicValues> {
        self.prove_impl(pk, stdin, MONEROCHANProverOpts::default(), MONEROCHANContext::default(), mode)
    }

    fn verify(
        &self,
        bundle: &MONEROCHANProofWithPublicValues,
        vkey: &MONEROCHANVerifyingKey,
    ) -> Result<(), MONEROCHANVerificationError> {
        if self.mock {
            tracing::warn!("using mock verifier");
            return Self::mock_verify(bundle, vkey);
        }
        verify_proof(self.inner(), self.version(), bundle, vkey)
    }
}

impl Default for CpuProver {
    fn default() -> Self {
        let prover = MONEROCHANProver::new();
        Self { prover, mock: false }
    }
}
