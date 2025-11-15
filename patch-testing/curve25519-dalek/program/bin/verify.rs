#![no_main]
monerochan_runtime::entrypoint!(main);

use ed25519_dalek::{
    Signature, Verifier, VerifyingKey,
};

/// Emits ED_ADD and ED_DECOMPRESS syscalls.
pub fn main() {
    let times = monerochan_runtime::io::read::<usize>();

    for _ in 0..times {
        let (msg, vk, sig) = monerochan_runtime::io::read::<(Vec<u8>, VerifyingKey, Signature)>();

        monerochan_runtime::io::commit(&vk.verify(&msg, &sig).is_ok());
    }
} 
