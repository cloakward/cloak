//! `cloak completions <SHELL>` — emit shell completion scripts.

use anyhow::Result;
use clap::CommandFactory;
use clap_complete::Shell;

use super::Cli;

/// Generate the completion script for the requested shell on stdout.
pub fn run(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    let bin = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, bin, &mut std::io::stdout());
    Ok(())
}
