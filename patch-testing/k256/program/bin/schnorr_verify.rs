#![no_main]
monerochan_runtime::entrypoint!(main);

use ecdsa_core::signature::Verifier;
use k256::schnorr::{Signature, VerifyingKey};

pub fn main() {
    let times = monerochan_runtime::io::read::<u8>();

    for _ in 0..times {
        monerochan_runtime::io::commit(&inner());
    }
}

fn inner() -> bool {
    let message: [u8; 32] = monerochan_runtime::io::read();
    let signature = monerochan_runtime::io::read_vec();
    let vkey_bytes = monerochan_runtime::io::read_vec();
    let vkey = VerifyingKey::from_bytes(vkey_bytes.as_slice()).unwrap();
    let signature = Signature::try_from(signature.as_slice()).unwrap();

    vkey.verify(&message, &signature).is_ok()
}
