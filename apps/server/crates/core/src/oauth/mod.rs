mod client;
mod discord;

pub use client::{OAuthClient, OAuthError, ProviderConfig, StartFlow, Tokens, DISCORD_PROVIDER};
pub use discord::{fetch_discord_user, DiscordUser};
