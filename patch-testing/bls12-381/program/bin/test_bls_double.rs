#![no_main]

use bls12_381::G1Projective;
monerochan_runtime::entrypoint!(main);

pub fn main() {
    use bls12_381::g1::G1Affine;

    let times = monerochan_lib::io::read::<u8>();

    for _ in 0..times {
        let val: Vec<u8> = monerochan_lib::io::read();

        let val = G1Affine::from_uncompressed(&val.try_into().expect("[u8; 96] for g1")).unwrap();
        let projective: G1Projective = val.into();
 
        let sum = projective.double();
        let sum_affine: G1Affine = sum.into();
        
        monerochan_lib::io::commit(&sum_affine.to_uncompressed().to_vec());
    }
}

