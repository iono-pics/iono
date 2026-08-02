use crate::config::Config;

pub fn init_config() -> Config {
    dotenvy::dotenv().ok();
    crate::telemetry::init();
    Config::from_env()
}
