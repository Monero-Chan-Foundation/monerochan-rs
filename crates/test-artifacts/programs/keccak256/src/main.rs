#![no_main]
monerochan_runtime::entrypoint!(main);

use tiny_keccak::{Hasher, Keccak};

pub fn main() {
    let num_cases = monerochan_runtime::io::read::<usize>();
    for _ in 0..num_cases {
        let input = monerochan_runtime::io::read::<Vec<u8>>();
        let mut hasher = Keccak::v256();
        hasher.update(&input);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        monerochan_runtime::io::commit(&output);
    }
}
