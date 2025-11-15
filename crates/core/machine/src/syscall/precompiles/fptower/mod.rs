mod fp;
mod fp2_addsub;
mod fp2_mul;

pub use fp::*;
pub use fp2_addsub::*;
pub use fp2_mul::*;

#[cfg(test)]
mod tests {
    use monerochan_stark::CpuProver;

    use monerochan_core_executor::Program;
    use test_artifacts::{
        BLS12381_FP2_ADDSUB_ELF, BLS12381_FP2_MUL_ELF, BLS12381_FP_ELF, BN254_FP2_ADDSUB_ELF,
        BN254_FP2_MUL_ELF, BN254_FP_ELF,
    };

    use crate::{io::MONEROCHANStdin, utils};

    #[test]
    fn test_bls12381_fp_ops() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP_ELF).unwrap();
        let stdin = MONEROCHANStdin::new();
        utils::run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }

    #[test]
    fn test_bls12381_fp2_addsub() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP2_ADDSUB_ELF).unwrap();
        let stdin = MONEROCHANStdin::new();
        utils::run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }

    #[test]
    fn test_bls12381_fp2_mul() {
        utils::setup_logger();
        let program = Program::from(BLS12381_FP2_MUL_ELF).unwrap();
        let stdin = MONEROCHANStdin::new();
        utils::run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }

    #[test]
    fn test_bn254_fp_ops() {
        utils::setup_logger();
        let program = Program::from(BN254_FP_ELF).unwrap();
        let stdin = MONEROCHANStdin::new();
        utils::run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }

    #[test]
    fn test_bn254_fp2_addsub() {
        utils::setup_logger();
        let program = Program::from(BN254_FP2_ADDSUB_ELF).unwrap();
        let stdin = MONEROCHANStdin::new();
        utils::run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }

    #[test]
    fn test_bn254_fp2_mul() {
        utils::setup_logger();
        let program = Program::from(BN254_FP2_MUL_ELF).unwrap();
        let stdin = MONEROCHANStdin::new();
        utils::run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }
}
