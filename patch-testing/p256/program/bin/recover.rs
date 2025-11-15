#![no_main]
monerochan_runtime::entrypoint!(main);

use p256::ecdsa::{RecoveryId, Signature, VerifyingKey};

pub fn main() {
    let times = monerochan_runtime::io::read::<u8>();

    for _ in 0..times {
        let vk = inner();
        monerochan_runtime::io::commit(&vk.map(|vk| vk.to_sec1_bytes()));
    }
}

fn inner() -> Option<VerifyingKey> {
    let (message, signature, recid_byte): (Vec<u8>, Signature, u8) = monerochan_runtime::io::read();
    let recid = RecoveryId::from_byte(recid_byte).unwrap();

    VerifyingKey::recover_from_prehash(&message, &signature, recid).ok()
}
