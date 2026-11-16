use actix_governor::governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;
use std::time::Duration;

use crate::error::AppError;

const BURST: u32 = 10;
const REPLENISH_EVERY: Duration = Duration::from_secs(10);
const PRUNE_ABOVE: usize = 100_000;

/// limits login attempts per account from one client address, so a guesser
/// pays for each account it targets without being able to lock the owner out
/// from another address
pub struct LoginThrottle {
    limiter: DefaultKeyedRateLimiter<[u8; 32]>,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        let quota = Quota::with_period(REPLENISH_EVERY)
            .unwrap_or_else(|| Quota::per_minute(NonZeroU32::MIN))
            .allow_burst(NonZeroU32::new(BURST).unwrap_or(NonZeroU32::MIN));
        Self {
            limiter: RateLimiter::keyed(quota),
        }
    }
}

impl LoginThrottle {
    /// counts an attempt against `identifier` from `client`
    ///
    /// # Errors
    ///
    /// Returns [`AppError::RateLimited`] when the budget for the pair is spent.
    pub fn check(&self, identifier: &str, client: Option<IpAddr>) -> Result<(), AppError> {
        if self.limiter.len() > PRUNE_ABOVE {
            self.limiter.retain_recent();
            self.limiter.shrink_to_fit();
        }
        self.limiter
            .check_key(&key(identifier, client))
            .map_err(|_| AppError::RateLimited)
    }
}

fn key(identifier: &str, client: Option<IpAddr>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(identifier.trim().to_lowercase().as_bytes());
    hasher.update([0]);
    if let Some(ip) = client {
        hasher.update(bucket(ip).to_string().as_bytes());
    }
    hasher.finalize().into()
}

/// one client usually controls a whole /64, so keying on the exact ipv6
/// address would let it rotate addresses for a fresh budget every attempt
fn bucket(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let masked = u128::from(v6) & (u128::MAX << 64);
            IpAddr::V6(Ipv6Addr::from(masked))
        }
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<IpAddr> {
        s.parse().ok()
    }

    #[test]
    fn attempts_beyond_the_burst_are_refused() {
        let throttle = LoginThrottle::default();
        for _ in 0..BURST {
            assert!(throttle.check("evie", ip("1.1.1.1")).is_ok());
        }
        assert!(matches!(
            throttle.check("evie", ip("1.1.1.1")),
            Err(AppError::RateLimited)
        ));
    }

    #[test]
    fn another_address_does_not_spend_the_owners_budget() {
        let throttle = LoginThrottle::default();
        for _ in 0..BURST + 5 {
            let _ = throttle.check("evie", ip("1.1.1.1"));
        }
        assert!(throttle.check("evie", ip("2.2.2.2")).is_ok());
    }

    #[test]
    fn rotating_within_an_ipv6_64_does_not_reset_the_budget() {
        let throttle = LoginThrottle::default();
        for i in 0..BURST {
            let _ = throttle.check("evie", ip(&format!("2001:db8:1:2::{i:x}")));
        }
        assert!(throttle.check("evie", ip("2001:db8:1:2:ffff::1")).is_err());
        assert!(throttle.check("evie", ip("2001:db8:1:3::1")).is_ok());
    }

    #[test]
    fn accounts_have_separate_budgets() {
        let throttle = LoginThrottle::default();
        for _ in 0..BURST + 5 {
            let _ = throttle.check("evie", ip("1.1.1.1"));
        }
        assert!(throttle.check("elle", ip("1.1.1.1")).is_ok());
    }

    #[test]
    fn case_and_padding_do_not_dodge_the_limit() {
        let throttle = LoginThrottle::default();
        for _ in 0..BURST {
            let _ = throttle.check("Evie", ip("1.1.1.1"));
        }
        assert!(throttle.check("  evie ", ip("1.1.1.1")).is_err());
    }
}
