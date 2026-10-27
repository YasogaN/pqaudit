use clap::Parser;
use pqaudit::cli::Cli;

#[tokio::main]
async fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // --help/--version print to stdout and exit 0; real usage errors
            // print to stderr and use our documented exit code 3.
            let code = if e.use_stderr() { 3 } else { 0 };
            let _ = e.print();
            std::process::exit(code);
        }
    };
    std::process::exit(pqaudit::app::run(cli).await);
}
