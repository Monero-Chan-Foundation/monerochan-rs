use monerochan::{include_elf, utils, ProverClient, MONEROCHANProofWithPublicValues, MONEROCHANStdin};

const ELF: &[u8] = include_elf!("ssz-withdrawals-program");

fn main() {
    // Generate proof.
    // utils::setup_tracer();
    utils::setup_logger();

    let stdin = MONEROCHANStdin::new();
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(ELF);
    let proof = client.prove(&pk, &stdin).run().expect("proving failed");

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof.save("proof-with-pis.bin").expect("saving proof failed");
    let deserialized_proof =
        MONEROCHANProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
