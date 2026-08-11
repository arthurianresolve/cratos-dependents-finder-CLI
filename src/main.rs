use anyhow::Result;
use clap::Parser;
use crate_dependent_repos::{Cli, cli::run};

#[tokio::main]
async fn main() -> Result<()> {
    run(Cli::parse()).await
}
