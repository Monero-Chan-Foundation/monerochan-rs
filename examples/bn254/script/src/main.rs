use monerochan::{include_elf, utils, ProverClient, MONEROCHANStdin};
pub const ELF: &[u8] = include_elf!("bn254-program");

fn main() {
    utils::setup_logger();

    let stdin = MONEROCHANStdin::new();

    let client = ProverClient::from_env();
    let (_public_values, report) = client.execute(ELF, &stdin).run().expect("failed to prove");

    println!("executed: {}", report);
}
