#![no_main]
monerochan_runtime::entrypoint!(main);

use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, PublicKey, Secp256k1,
};

pub fn main() {
    let times = monerochan_runtime::io::read::<u8>();

    for _ in 0..times {
        let pubkey = inner_recover();
        monerochan_runtime::io::commit(&pubkey);
    }
}

fn inner_recover() -> Option<PublicKey> {
    let recid: i32 = monerochan_runtime::io::read();
    let msg = monerochan_runtime::io::read_vec();
    let sig: [u8; 64] = monerochan_runtime::io::read_vec().try_into().unwrap();
    let recid = RecoveryId::from_i32(recid).unwrap();
    let message = Message::from_digest_slice(&msg).unwrap();
    let sig = RecoverableSignature::from_compact(&sig, recid).unwrap();
    let secp = Secp256k1::new();

    secp.recover_ecdsa(&message, &sig).ok()
}
