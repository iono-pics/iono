//! Typed client for the Cloudflare v4 API, adapted from the cloudflare-rs crate.

mod client;
pub mod endpoints;

pub use client::{ApiError, CloudflareClient, Credentials, Endpoint};
