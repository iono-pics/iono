use crate::config::Config;

/// loads `.env`, starts telemetry and reads the config, exiting with a clear
/// message when the environment is wrong
pub fn init_config() -> Config {
    dotenvy::dotenv().ok();
    crate::telemetry::init();
    Config::from_env().unwrap_or_else(|e| fatal("read the configuration", &e))
}

/// logs why startup failed and exits non-zero, with no backtrace
pub fn fatal(context: &str, error: &dyn std::fmt::Debug) -> ! {
    tracing::error!("failed to {context}: {error:?}");
    eprintln!("failed to {context}: {error:?}");
    std::process::exit(1)
}
