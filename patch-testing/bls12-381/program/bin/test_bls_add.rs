
#![no_main]
monerochan_runtime::entrypoint!(main);

pub fn main() {
    use bls12_381::g1::G1Affine;

    let times = monerochan_lib::io::read::<u8>();

    for _ in 0..times {
        let val: Vec<u8> = monerochan_lib::io::read();
        let val2: Vec<u8> = monerochan_lib::io::read();

        let val = G1Affine::from_uncompressed(&val.try_into().expect("[u8; 96] for g1")).unwrap();
        let val2 = G1Affine::from_uncompressed(&val2.try_into().expect("[u8; 96] for g1")).unwrap();

        // The Rust test actually does projective addition, but this should be equivalent.
        let sum = val.add_affine(&val2);
        
        monerochan_lib::io::commit(&sum.to_uncompressed().to_vec());
    }
}

