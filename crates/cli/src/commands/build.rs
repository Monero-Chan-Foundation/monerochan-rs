use anyhow::Result;
use clap::Parser;
use monerochan_build::{execute_build_program, BuildArgs};

#[derive(Parser)]
#[command(name = "build", about = "Compile an MONEROCHAN program")]
pub struct BuildCmd {
    #[command(flatten)]
    build_args: BuildArgs,
}

impl BuildCmd {
    pub fn run(&self) -> Result<()> {
        execute_build_program(&self.build_args, None)?;

        Ok(())
    }
}
