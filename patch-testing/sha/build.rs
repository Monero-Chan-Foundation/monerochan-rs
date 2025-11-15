use monerochan_build::BuildArgs;

fn main() {
    monerochan_build::build_program_with_args(
        "./program",
        BuildArgs { features: vec!["v0-9-9".to_string()], ..Default::default() },
    );
    monerochan_build::build_program_with_args(
        "./program",
        BuildArgs { features: vec!["v0-10-6".to_string()], ..Default::default() },
    );
    monerochan_build::build_program_with_args(
        "./program",
        BuildArgs { features: vec!["v0-10-8".to_string()], ..Default::default() },
    );
}
