//! A program that verifies a Groth16 proof in MONEROCHAN.

#![no_main]
monerochan_runtime::entrypoint!(main);

use monerochan_verifier::Groth16Verifier;

pub fn main() {
    // Read the proof, public values, and vkey hash from the input stream.
    let proof = monerochan_runtime::io::read_vec();
    let monerochan_public_values = monerochan_runtime::io::read_vec();
    let monerochan_vkey_hash: String = monerochan_runtime::io::read();

    // Verify the groth16 proof.
    let groth16_vk = *monerochan_verifier::GROTH16_VK_BYTES;
    println!("cycle-tracker-start: verify");
    let result = Groth16Verifier::verify(&proof, &monerochan_public_values, &monerochan_vkey_hash, groth16_vk);
    println!("cycle-tracker-end: verify");

    match result {
        Ok(()) => {
            println!("Proof is valid");
        }
        Err(e) => {
            println!("Error verifying proof: {:?}", e);
        }
    }
}
