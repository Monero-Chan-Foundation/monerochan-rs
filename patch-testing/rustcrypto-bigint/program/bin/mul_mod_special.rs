#![no_main]
monerochan_runtime::entrypoint!(main);

use crypto_bigint::{Encoding, Limb, Uint};

pub fn main() {
    let times = monerochan_lib::io::read::<u8>();

    for _ in 0..times {
        let a: [u32; 8] = monerochan_lib::io::read::<Vec<u32>>().try_into().unwrap();
        let b: [u32; 8] = monerochan_lib::io::read::<Vec<u32>>().try_into().unwrap();
        let a = Uint::<8>::from_words(a);
        let b = Uint::<8>::from_words(b);

        let c: u32 = 356u32;
        let c = Limb(c);
        let result = a.mul_mod_special(&b, c);

        monerochan_lib::io::commit(&result.to_be_bytes().to_vec());
    }
}
