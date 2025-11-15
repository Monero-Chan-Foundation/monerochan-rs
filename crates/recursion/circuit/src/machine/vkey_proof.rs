use std::marker::PhantomData;

use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_commit::Mmcs;
use p3_field::AbstractField;
use p3_matrix::dense::RowMajorMatrix;
use serde::{Deserialize, Serialize};
use monerochan_recursion_compiler::ir::{Builder, Felt};
use monerochan_recursion_core::DIGEST_SIZE;
use monerochan_stark::{
    air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, Com, InnerChallenge, OpeningProof,
    StarkGenericConfig, StarkMachine,
};

use crate::{
    challenger::DuplexChallengerVariable,
    constraints::RecursiveVerifierConstraintFolder,
    hash::{FieldHasher, FieldHasherVariable},
    merkle_tree::{verify, MerkleProof},
    stark::MerkleProofVariable,
    witness::{WitnessWriter, Witnessable},
    BabyBearFriConfig, BabyBearFriConfigVariable, CircuitConfig, TwoAdicPcsProofVariable,
};

use super::{
    PublicValuesOutputDigest, MONEROCHANCompressShape, MONEROCHANCompressVerifier, MONEROCHANCompressWitnessValues,
    MONEROCHANCompressWitnessVariable,
};

/// A program to verify a batch of recursive proofs and aggregate their public values.
#[derive(Debug, Clone, Copy)]
pub struct MONEROCHANMerkleProofVerifier<C, SC> {
    _phantom: PhantomData<(C, SC)>,
}

/// The shape of the compress proof with vk validation proofs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MONEROCHANCompressWithVkeyShape {
    pub compress_shape: MONEROCHANCompressShape,
    pub merkle_tree_height: usize,
}

/// Witness layout for the compress stage verifier.
pub struct MONEROCHANMerkleProofWitnessVariable<
    C: CircuitConfig<F = BabyBear>,
    SC: FieldHasherVariable<C> + BabyBearFriConfigVariable<C>,
> {
    /// The shard proofs to verify.
    pub vk_merkle_proofs: Vec<MerkleProofVariable<C, SC>>,
    /// Hinted values to enable dummy digests.
    pub values: Vec<SC::DigestVariable>,
    /// The root of the merkle tree.
    pub root: SC::DigestVariable,
}

/// An input layout for the reduce verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SC::Digest: Serialize"))]
#[serde(bound(deserialize = "SC::Digest: Deserialize<'de>"))]
pub struct MONEROCHANMerkleProofWitnessValues<SC: FieldHasher<BabyBear>> {
    pub vk_merkle_proofs: Vec<MerkleProof<BabyBear, SC>>,
    pub values: Vec<SC::Digest>,
    pub root: SC::Digest,
}

impl<C, SC> MONEROCHANMerkleProofVerifier<C, SC>
where
    SC: BabyBearFriConfigVariable<C>,
    C: CircuitConfig<F = SC::Val, EF = SC::Challenge>,
{
    /// Verify (via Merkle tree) that the vkey digests of a proof belong to a specified set (encoded
    /// the Merkle tree proofs in input).
    pub fn verify(
        builder: &mut Builder<C>,
        digests: Vec<SC::DigestVariable>,
        input: MONEROCHANMerkleProofWitnessVariable<C, SC>,
        value_assertions: bool,
    ) {
        let MONEROCHANMerkleProofWitnessVariable { vk_merkle_proofs, values, root } = input;
        for ((proof, value), expected_value) in
            vk_merkle_proofs.into_iter().zip(values).zip(digests)
        {
            verify(builder, proof, value, root);
            if value_assertions {
                SC::assert_digest_eq(builder, expected_value, value);
            } else {
                SC::assert_digest_eq(builder, value, value);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MONEROCHANCompressWithVKeyVerifier<C, SC, A> {
    _phantom: PhantomData<(C, SC, A)>,
}

/// Witness layout for the verifier of the proof shape phase of the compress stage.
pub struct MONEROCHANCompressWithVKeyWitnessVariable<
    C: CircuitConfig<F = BabyBear>,
    SC: BabyBearFriConfigVariable<C>,
> {
    pub compress_var: MONEROCHANCompressWitnessVariable<C, SC>,
    pub merkle_var: MONEROCHANMerkleProofWitnessVariable<C, SC>,
}

/// An input layout for the verifier of the proof shape phase of the compress stage.
pub struct MONEROCHANCompressWithVKeyWitnessValues<SC: StarkGenericConfig + FieldHasher<BabyBear>> {
    pub compress_val: MONEROCHANCompressWitnessValues<SC>,
    pub merkle_val: MONEROCHANMerkleProofWitnessValues<SC>,
}

impl<C, SC, A> MONEROCHANCompressWithVKeyVerifier<C, SC, A>
where
    SC: BabyBearFriConfigVariable<
        C,
        FriChallengerVariable = DuplexChallengerVariable<C>,
        DigestVariable = [Felt<BabyBear>; DIGEST_SIZE],
    >,
    C: CircuitConfig<F = SC::Val, EF = SC::Challenge, Bit = Felt<BabyBear>>,
    <SC::ValMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>: Clone,
    A: MachineAir<SC::Val> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
{
    /// Verify the proof shape phase of the compress stage.
    pub fn verify(
        builder: &mut Builder<C>,
        machine: &StarkMachine<SC, A>,
        input: MONEROCHANCompressWithVKeyWitnessVariable<C, SC>,
        value_assertions: bool,
        kind: PublicValuesOutputDigest,
    ) {
        let values = input
            .compress_var
            .vks_and_proofs
            .iter()
            .map(|(vk, _)| vk.hash(builder))
            .collect::<Vec<_>>();
        let vk_root = input.merkle_var.root.map(|x| builder.eval(x));
        MONEROCHANMerkleProofVerifier::verify(builder, values, input.merkle_var, value_assertions);
        MONEROCHANCompressVerifier::verify(builder, machine, input.compress_var, vk_root, kind);
    }
}

impl<SC: BabyBearFriConfig + FieldHasher<BabyBear>> MONEROCHANCompressWithVKeyWitnessValues<SC> {
    pub fn shape(&self) -> MONEROCHANCompressWithVkeyShape {
        let merkle_tree_height = self.merkle_val.vk_merkle_proofs.first().unwrap().path.len();
        MONEROCHANCompressWithVkeyShape { compress_shape: self.compress_val.shape(), merkle_tree_height }
    }
}

impl MONEROCHANMerkleProofWitnessValues<BabyBearPoseidon2> {
    pub fn dummy(num_proofs: usize, height: usize) -> Self {
        let dummy_digest = [BabyBear::zero(); DIGEST_SIZE];
        let vk_merkle_proofs =
            vec![MerkleProof { index: 0, path: vec![dummy_digest; height] }; num_proofs];
        let values = vec![dummy_digest; num_proofs];

        Self { vk_merkle_proofs, values, root: dummy_digest }
    }
}

impl MONEROCHANCompressWithVKeyWitnessValues<BabyBearPoseidon2> {
    pub fn dummy<A: MachineAir<BabyBear>>(
        machine: &StarkMachine<BabyBearPoseidon2, A>,
        shape: &MONEROCHANCompressWithVkeyShape,
    ) -> Self {
        let compress_val =
            MONEROCHANCompressWitnessValues::<BabyBearPoseidon2>::dummy(machine, &shape.compress_shape);
        let num_proofs = compress_val.vks_and_proofs.len();
        let merkle_val = MONEROCHANMerkleProofWitnessValues::<BabyBearPoseidon2>::dummy(
            num_proofs,
            shape.merkle_tree_height,
        );
        Self { compress_val, merkle_val }
    }
}

impl<C: CircuitConfig<F = BabyBear, EF = InnerChallenge>, SC: BabyBearFriConfigVariable<C>>
    Witnessable<C> for MONEROCHANCompressWithVKeyWitnessValues<SC>
where
    Com<SC>: Witnessable<C, WitnessVariable = <SC as FieldHasherVariable<C>>::DigestVariable>,
    // This trait bound is redundant, but Rust-Analyzer is not able to infer it.
    SC: FieldHasher<BabyBear>,
    <SC as FieldHasher<BabyBear>>::Digest: Witnessable<C, WitnessVariable = SC::DigestVariable>,
    OpeningProof<SC>: Witnessable<C, WitnessVariable = TwoAdicPcsProofVariable<C, SC>>,
{
    type WitnessVariable = MONEROCHANCompressWithVKeyWitnessVariable<C, SC>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        MONEROCHANCompressWithVKeyWitnessVariable {
            compress_var: self.compress_val.read(builder),
            merkle_var: self.merkle_val.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.compress_val.write(witness);
        self.merkle_val.write(witness);
    }
}
