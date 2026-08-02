//! Typed client for CFV4 API, code inspired by cloudflare-rs crate.
//! I might turn this into its own seperate crate and publish it if
//! i feel motivated to flesh it out.

mod client;
pub mod endpoints;

pub use client::{ApiError, CloudflareClient, Credentials, Endpoint};
