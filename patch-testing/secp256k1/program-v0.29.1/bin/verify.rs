#![no_main]
monerochan_runtime::entrypoint!(main);

use secp256k1::{ecdsa::Signature, Message, PublicKey};

pub fn main() {
    let times = monerochan_runtime::io::read::<u8>();

    for i in 0..times {
        println!("{}", i);
        monerochan_runtime::io::commit(&inner_verify());
    }
}

fn inner_verify() -> bool {
    let msg_digest = monerochan_runtime::io::read_vec();
    let signature = monerochan_runtime::io::read_vec();
    let message = Message::from_digest_slice(&msg_digest).unwrap();
    let signature = Signature::from_der(&signature).unwrap();
    let pubkey = monerochan_runtime::io::read::<PublicKey>();
    let secp = secp256k1::Secp256k1::new();

    secp.verify_ecdsa(&message, &signature, &pubkey).is_ok()
}
