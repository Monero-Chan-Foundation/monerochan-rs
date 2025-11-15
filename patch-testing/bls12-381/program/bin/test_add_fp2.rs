#![no_main]
monerochan_runtime::entrypoint!(main);

pub fn main() {
    use bls12_381::fp2::Fp2;

    let times = monerochan_lib::io::read::<u8>();

    for _ in 0..times {
        let val1: Vec<u8> = monerochan_lib::io::read();
        let val2: Vec<u8> = monerochan_lib::io::read();

        let val1 = Fp2::from_bytes(&val1.try_into().expect("[u8; 96] for fp2")).unwrap();
        let val2 = Fp2::from_bytes(&val2.try_into().expect("[u8; 96] for fp2")).unwrap();

        let sum = val1 + val2;

        monerochan_lib::io::commit(&sum.to_bytes().to_vec());
    }
}