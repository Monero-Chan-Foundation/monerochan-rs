use anyhow::Result;
use clap::{Args, Parser};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
};
use yansi::Paint;

#[derive(Args)]
#[group(required = true, multiple = false)]
struct TemplateType {
    /// Use the `bare` template which includes just a program and script.
    #[arg(long)]
    bare: bool,
}

#[derive(Parser)]
#[command(name = "new", about = "Setup a new project that runs inside the MONEROCHAN.")]
pub struct NewCmd {
    /// The name of the project.
    name: String,

    /// The template to use for the project.
    #[command(flatten)]
    template: TemplateType,

    /// Version of monerochan-project-template to use (branch or tag).
    #[arg(long, default_value = "main")]
    version: String,
}

const TEMPLATE_REPOSITORY_URL: &str =
    "https://github.com/Monero-Chan-Foundation/monerochan-project-template";

impl NewCmd {
    pub fn run(&self) -> Result<()> {
        let root = Path::new(&self.name);

        // Create the root directory if it doesn't exist.
        if !root.exists() {
            fs::create_dir(&self.name)?;
        }

        // Clone the repository with the specified version.
        let mut command = Command::new("git");

        command
            .arg("clone")
            .arg("--branch")
            .arg(&self.version)
            .arg("--quiet")
            .arg(TEMPLATE_REPOSITORY_URL)
            .arg(root.as_os_str())
            .arg("--depth=1");

        // Suppress git output.
        command.stdout(Stdio::null()).stderr(Stdio::piped());

        let output = command.output().expect("failed to execute command");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to clone repository: {}", stderr));
        }

        // Remove the .git directory.
        fs::remove_dir_all(root.join(".git"))?;

        println!(
            " \x1b[1m{}\x1b[0m {}",
            Paint::green("Initialized"),
            self.name
        );

        Ok(())
    }
}
