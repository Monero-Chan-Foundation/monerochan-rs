#![no_main]
monerochan_runtime::entrypoint!(main);

use ecdsa_core::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};

pub fn main() {
    let times = monerochan_runtime::io::read::<u8>();

    for _ in 0..times {
        monerochan_runtime::io::commit(&inner());
    }
}

fn inner() -> bool {
    let (message, signature, vkey_bytes): (Vec<u8>, Signature, Vec<u8>) = monerochan_runtime::io::read();
    let vkey = VerifyingKey::from_sec1_bytes(&vkey_bytes).unwrap();

    vkey.verify(&message, &signature).is_ok()
}
