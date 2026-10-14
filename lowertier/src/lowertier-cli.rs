#[tokio::main]
async fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(lowertier::cli::run().await)
}
