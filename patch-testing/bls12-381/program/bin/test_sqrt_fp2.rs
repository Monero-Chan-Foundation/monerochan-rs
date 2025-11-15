#![no_main]
monerochan_runtime::entrypoint!(main);

pub fn main() {
    let times = monerochan_lib::io::read::<u8>();

    for i in 0..times {
        println!("Running test {}", i);

        let val: Vec<u8> = monerochan_lib::io::read();

        let val = bls12_381::fp2::Fp2::from_bytes(&val.try_into().expect("[u8; 96] for fp")).unwrap();

        let sqrt_bytes = val.sqrt().into_option().map(|v| v.to_bytes().to_vec());

        monerochan_lib::io::commit(&sqrt_bytes);
    }
}
