//! Types and methods for subproof verification inside the [`crate::Executor`].

use monerochan_stark::{
    baby_bear_poseidon2::BabyBearPoseidon2, MachineVerificationError, MONEROCHANReduceProof,
    StarkVerifyingKey,
};

/// Verifier used in runtime when `monerochan_runtime::precompiles::verify::verify_monerochan_proof` is called. This
/// is then used to sanity check that the user passed in the correct proof; the actual constraints
/// happen in the recursion layer.
///
/// This needs to be passed in rather than written directly since the actual implementation relies
/// on crates in recursion that depend on monerochan-core.
pub trait SubproofVerifier: Sync + Send {
    /// Verify a deferred proof.
    fn verify_deferred_proof(
        &self,
        proof: &MONEROCHANReduceProof<BabyBearPoseidon2>,
        vk: &StarkVerifyingKey<BabyBearPoseidon2>,
        vk_hash: [u32; 8],
        committed_value_digest: [u32; 8],
    ) -> Result<(), MachineVerificationError<BabyBearPoseidon2>>;
}

/// A dummy verifier which does nothing.
pub struct NoOpSubproofVerifier;

impl SubproofVerifier for NoOpSubproofVerifier {
    fn verify_deferred_proof(
        &self,
        _proof: &MONEROCHANReduceProof<BabyBearPoseidon2>,
        _vk: &StarkVerifyingKey<BabyBearPoseidon2>,
        _vk_hash: [u32; 8],
        _committed_value_digest: [u32; 8],
    ) -> Result<(), MachineVerificationError<BabyBearPoseidon2>> {
        Ok(())
    }
}
