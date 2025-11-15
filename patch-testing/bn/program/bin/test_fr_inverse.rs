#![no_main]
monerochan_runtime::entrypoint!(main);

pub fn main() {
    let times = monerochan_lib::io::read::<u8>();

    for _ in 0..times {
        let val: Vec<u8> = monerochan_lib::io::read();
        let val = substrate_bn::Fr::from_slice(&val).unwrap();
        let inverse = val.inverse().unwrap();

        let mut inverse_bytes = [0u8; 32];
        inverse.to_big_endian(&mut inverse_bytes).unwrap();
        monerochan_lib::io::commit(&inverse_bytes.to_vec());
    }
}
