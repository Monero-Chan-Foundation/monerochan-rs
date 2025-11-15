mod air;

pub use air::*;

#[cfg(test)]
mod tests {

    use monerochan_core_executor::Program;
    use monerochan_curves::{params::FieldParameters, uint256::U256Field, utils::biguint_from_limbs};
    use monerochan_stark::CpuProver;
    use test_artifacts::UINT256_MUL_ELF;

    use crate::{
        io::MONEROCHANStdin,
        utils::{self, run_test},
    };

    #[test]
    fn test_uint256_mul() {
        utils::setup_logger();
        let program = Program::from(UINT256_MUL_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program, MONEROCHANStdin::new()).unwrap();
    }

    #[test]
    fn test_uint256_modulus() {
        assert_eq!(biguint_from_limbs(U256Field::MODULUS), U256Field::modulus());
    }
}
