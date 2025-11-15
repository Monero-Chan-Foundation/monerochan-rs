#![no_main]
monerochan_runtime::entrypoint!(main);

use monerochan_verifier::PlonkVerifier;

fn main() {
    // Read the proof, public values, and vkey hash from the input stream.
    let proof = monerochan_runtime::io::read_vec();
    let monerochan_public_values = monerochan_runtime::io::read_vec();
    let monerochan_vkey_hash: String = monerochan_runtime::io::read();

    // Verify the groth16 proof.
    let plonk_vk = *monerochan_verifier::PLONK_VK_BYTES;
    let result =
        PlonkVerifier::verify(&proof, &monerochan_public_values, &monerochan_vkey_hash, plonk_vk).unwrap();
}
