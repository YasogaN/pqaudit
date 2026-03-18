use clap::Parser;
use pqaudit::cli::Cli;

fn main() {
    let _args = Cli::parse();
    println!("pqaudit v{}", env!("CARGO_PKG_VERSION"));
}
