//! password checks for protected files and pastes. a video plays as dozens of
//! range requests that each carry the password, and argon2 on every one is
//! both slow and an easy way to exhaust memory. a credential that verified
//! once is trusted for a while, and the slow path is rate limited per client

use actix_governor::governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use iono_core::AppError;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const REMEMBER_FOR: Duration = Duration::from_secs(10 * 60);
const MAX_REMEMBERED: usize = 50_000;
const SLOW_CHECKS_BURST: u32 = 30;
const SLOW_CHECK_EVERY: Duration = Duration::from_secs(2);

pub struct Unlocker {
    verified: Mutex<HashMap<[u8; 32], Instant>>,
    limiter: DefaultKeyedRateLimiter<IpAddr>,
}

impl Default for Unlocker {
    fn default() -> Self {
        let quota = Quota::with_period(SLOW_CHECK_EVERY)
            .expect("slow check period is not zero")
            .allow_burst(NonZeroU32::new(SLOW_CHECKS_BURST).expect("burst is not zero"));
        Self {
            verified: Mutex::new(HashMap::new()),
            limiter: RateLimiter::keyed(quota),
        }
    }
}

impl Unlocker {
    /// `stored` is part of the key so changing a password forgets every
    /// credential remembered for the old one
    pub async fn check<F, Fut>(
        &self,
        client: Option<IpAddr>,
        resource_id: &str,
        stored: &str,
        provided: &str,
        slow_check: F,
    ) -> Result<bool, AppError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<bool, AppError>>,
    {
        let key = remember_key(resource_id, stored, provided);
        if self.remembers(&key) {
            return Ok(true);
        }

        if let Some(ip) = client {
            if self.limiter.check_key(&ip).is_err() {
                return Err(AppError::RateLimited);
            }
        }

        let ok = slow_check().await?;
        if ok {
            self.remember(key);
        }
        Ok(ok)
    }

    // the map holds only expiry times, so a poisoned lock is still safe to use
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Instant>> {
        self.verified
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn remembers(&self, key: &[u8; 32]) -> bool {
        let verified = self.lock();
        verified
            .get(key)
            .is_some_and(|until| *until > Instant::now())
    }

    fn remember(&self, key: [u8; 32]) {
        let now = Instant::now();
        let mut verified = self.lock();
        if verified.len() >= MAX_REMEMBERED {
            verified.retain(|_, until| *until > now);
            self.limiter.retain_recent();
            // still full means a flood of distinct valid credentials, forgetting
            // them only costs those viewers one more slow check
            if verified.len() >= MAX_REMEMBERED {
                verified.clear();
            }
        }
        verified.insert(key, now + REMEMBER_FOR);
    }
}

fn remember_key(resource_id: &str, stored: &str, provided: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in [resource_id, stored, provided] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const IP: Option<IpAddr> = Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    #[tokio::test]
    async fn a_verified_credential_skips_the_slow_check_next_time() {
        let unlocker = Unlocker::default();
        let calls = AtomicUsize::new(0);
        for _ in 0..5 {
            let ok = unlocker
                .check(IP, "f1", "hash", "pw", || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(true)
                })
                .await
                .unwrap();
            assert!(ok);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_wrong_credential_is_never_remembered() {
        let unlocker = Unlocker::default();
        let calls = AtomicUsize::new(0);
        for _ in 0..3 {
            let ok = unlocker
                .check(IP, "f1", "hash", "wrong", || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(false)
                })
                .await
                .unwrap();
            assert!(!ok);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_new_password_forgets_the_old_one() {
        let unlocker = Unlocker::default();
        unlocker
            .check(IP, "f1", "old-hash", "pw", || async { Ok(true) })
            .await
            .unwrap();

        let ok = unlocker
            .check(IP, "f1", "new-hash", "pw", || async { Ok(false) })
            .await
            .unwrap();
        assert!(!ok, "the old password must not unlock after a change");
    }

    #[tokio::test]
    async fn guessing_is_rate_limited_per_client() {
        let unlocker = Unlocker::default();
        let mut limited = false;
        for i in 0..SLOW_CHECKS_BURST + 5 {
            let result = unlocker
                .check(IP, "f1", "hash", &format!("guess{i}"), || async {
                    Ok(false)
                })
                .await;
            if matches!(result, Err(AppError::RateLimited)) {
                limited = true;
                break;
            }
        }
        assert!(limited, "guesses were never limited");
    }

    #[test]
    fn keys_do_not_collide_across_field_boundaries() {
        assert_ne!(remember_key("ab", "c", "d"), remember_key("a", "bc", "d"));
    }
}
