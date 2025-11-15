#![no_main]

monerochan_runtime::entrypoint!(main);

use monerochan_runtime::lib::bls12381::decompress_pubkey;

pub fn main() {
    let compressed_key: [u8; 48] = monerochan_runtime::io::read_vec().try_into().unwrap();

    for _ in 0..4 {
        println!("before: {:?}", compressed_key);

        let decompressed_key = decompress_pubkey(&compressed_key).unwrap();

        println!("after: {:?}", decompressed_key);
        monerochan_runtime::io::commit_slice(&decompressed_key);
    }
}
