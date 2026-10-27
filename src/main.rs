use clap::Parser;
use pqaudit::cli::Cli;

#[tokio::main]
async fn main() {
    let cli = Cli::try_parse().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(3);
    });
    std::process::exit(pqaudit::app::run(cli).await);
}
