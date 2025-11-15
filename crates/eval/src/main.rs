use anyhow::Result;
use monerochan_eval::evaluate_performance;
use monerochan_prover::components::CpuProverComponents;
use monerochan_stark::MONEROCHANProverOpts;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = MONEROCHANProverOpts::auto();
    evaluate_performance::<CpuProverComponents>(opts).await
}
