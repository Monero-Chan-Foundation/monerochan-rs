//! # MONEROCHAN CUDA Prover
//!
//! A prover that uses the CUDA to execute and prove programs.

pub mod builder;
pub mod prove;

use anyhow::Result;
use prove::CudaProveBuilder;
use monerochan_core_executor::MONEROCHANContextBuilder;
use monerochan_core_machine::io::MONEROCHANStdin;
use monerochan_cuda::{MoongateServer, MONEROCHANCudaProver};
use monerochan_prover::{components::CpuProverComponents, MONEROCHANProver};

use crate::{
    cpu::execute::CpuExecuteBuilder, install::try_install_circuit_artifacts, Prover, MONEROCHANProof,
    MONEROCHANProofMode, MONEROCHANProofWithPublicValues, MONEROCHANProvingKey, MONEROCHANVerifyingKey,
};

/// A prover that uses the CPU for execution and the CUDA for proving.
pub struct CudaProver {
    pub(crate) cpu_prover: MONEROCHANProver<CpuProverComponents>,
    pub(crate) cuda_prover: MONEROCHANCudaProver,
}

impl CudaProver {
    /// Creates a new [`CudaProver`].
    pub fn new(prover: MONEROCHANProver, moongate_server: MoongateServer) -> Self {
        let cuda_prover = MONEROCHANCudaProver::new(moongate_server);
        Self {
            cpu_prover: prover,
            cuda_prover: cuda_prover.expect("Failed to initialize CUDA prover"),
        }
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
    /// let client = ProverClient::builder().cuda().build();
    /// let (public_values, execution_report) = client.execute(elf, &stdin).run().unwrap();
    /// ```
    pub fn execute<'a>(&'a self, elf: &'a [u8], stdin: &MONEROCHANStdin) -> CpuExecuteBuilder<'a> {
        CpuExecuteBuilder {
            prover: &self.cpu_prover,
            elf,
            stdin: stdin.clone(),
            context_builder: MONEROCHANContextBuilder::default(),
        }
    }

    /// Creates a new [`CudaProveBuilder`] for proving a program on the CUDA.
    ///
    /// # Details
    /// The builder is used for only the [`crate::CudaProver`] client type.
    ///
    /// # Example
    /// ```rust,no_run
    /// use monerochan::{include_elf, Prover, ProverClient, MONEROCHANStdin};
    ///
    /// let elf = &[1, 2, 3];
    /// let stdin = MONEROCHANStdin::new();
    ///
    /// let client = ProverClient::builder().cuda().build();
    /// let (pk, vk) = client.setup(elf);
    /// let proof = client.prove(&pk, &stdin).run().unwrap();
    /// ```
    pub fn prove<'a>(&'a self, pk: &'a MONEROCHANProvingKey, stdin: &'a MONEROCHANStdin) -> CudaProveBuilder<'a> {
        CudaProveBuilder { prover: self, mode: MONEROCHANProofMode::Core, pk, stdin: stdin.clone() }
    }

    /// Proves the given program on the given input in the given proof mode.
    ///
    /// Returns the cycle count in addition to the proof.
    pub fn prove_with_cycles(
        &self,
        pk: &MONEROCHANProvingKey,
        stdin: &MONEROCHANStdin,
        kind: MONEROCHANProofMode,
    ) -> Result<(MONEROCHANProofWithPublicValues, u64)> {
        // Generate the core proof.
        let proof = self.cuda_prover.prove_core_stateless(pk, stdin)?;
        // TODO: Return the prover gas
        let cycles = proof.cycles;
        if kind == MONEROCHANProofMode::Core {
            let proof_with_pv = MONEROCHANProofWithPublicValues::new(
                MONEROCHANProof::Core(proof.proof.0),
                proof.public_values,
                self.version().to_string(),
            );
            return Ok((proof_with_pv, cycles));
        }

        // Generate the compressed proof.
        let deferred_proofs =
            stdin.proofs.iter().map(|(reduce_proof, _)| reduce_proof.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.cuda_prover.compress(&pk.vk, proof, deferred_proofs)?;
        if kind == MONEROCHANProofMode::Compressed {
            let proof_with_pv = MONEROCHANProofWithPublicValues::new(
                MONEROCHANProof::Compressed(Box::new(reduce_proof)),
                public_values,
                self.version().to_string(),
            );
            return Ok((proof_with_pv, cycles));
        }

        // Generate the shrink proof.
        let compress_proof = self.cuda_prover.shrink(reduce_proof)?;

        // Genenerate the wrap proof.
        let outer_proof = self.cuda_prover.wrap_bn254(compress_proof)?;

        if kind == MONEROCHANProofMode::Plonk {
            let plonk_bn254_artifacts = if monerochan_prover::build::monerochan_dev_mode() {
                monerochan_prover::build::try_build_plonk_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts("plonk")
            };
            let proof = self.cpu_prover.wrap_plonk_bn254(outer_proof, &plonk_bn254_artifacts);
            let proof_with_pv = MONEROCHANProofWithPublicValues::new(
                MONEROCHANProof::Plonk(proof),
                public_values,
                self.version().to_string(),
            );
            return Ok((proof_with_pv, cycles));
        } else if kind == MONEROCHANProofMode::Groth16 {
            let groth16_bn254_artifacts = if monerochan_prover::build::monerochan_dev_mode() {
                monerochan_prover::build::try_build_groth16_bn254_artifacts_dev(
                    &outer_proof.vk,
                    &outer_proof.proof,
                )
            } else {
                try_install_circuit_artifacts("groth16")
            };

            let proof = self.cpu_prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
            let proof_with_pv = MONEROCHANProofWithPublicValues::new(
                MONEROCHANProof::Groth16(proof),
                public_values,
                self.version().to_string(),
            );
            return Ok((proof_with_pv, cycles));
        }

        unreachable!()
    }
}

impl Prover<CpuProverComponents> for CudaProver {
    fn setup(&self, elf: &[u8]) -> (MONEROCHANProvingKey, MONEROCHANVerifyingKey) {
        let (pk, vk) = self.cuda_prover.setup(elf).unwrap();
        (pk, vk)
    }

    fn inner(&self) -> &MONEROCHANProver<CpuProverComponents> {
        &self.cpu_prover
    }

    fn prove(
        &self,
        pk: &MONEROCHANProvingKey,
        stdin: &MONEROCHANStdin,
        kind: MONEROCHANProofMode,
    ) -> Result<MONEROCHANProofWithPublicValues> {
        self.prove_with_cycles(pk, stdin, kind).map(|(p, _)| p)
    }
}

impl Default for CudaProver {
    fn default() -> Self {
        Self::new(MONEROCHANProver::new(), MoongateServer::default())
    }
}
