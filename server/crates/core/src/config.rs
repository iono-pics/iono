use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub gateway_port: u16,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            gateway_port: env::var("GATEWAY_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .expect("GATEWAY_PORT malformed"),
        }
    }
}
