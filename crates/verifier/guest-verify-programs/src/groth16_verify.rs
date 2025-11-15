#![no_main]
monerochan_runtime::entrypoint!(main);

use monerochan_verifier::Groth16Verifier;

fn main() {
    // Read the proof, public values, and vkey hash from the input stream.
    let proof = monerochan_runtime::io::read_vec();
    let monerochan_public_values = monerochan_runtime::io::read_vec();
    let monerochan_vkey_hash: String = monerochan_runtime::io::read();

    // Verify the plonk proof.
    let groth16_vk = *monerochan_verifier::GROTH16_VK_BYTES;
    let result =
        Groth16Verifier::verify(&proof, &monerochan_public_values, &monerochan_vkey_hash, groth16_vk).unwrap();
}
