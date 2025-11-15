use serde::{Deserialize, Serialize};

pub use monerochan_stark::{Groth16Bn254Proof, PlonkBn254Proof};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofBn254 {
    Plonk(PlonkBn254Proof),
    Groth16(Groth16Bn254Proof),
}
