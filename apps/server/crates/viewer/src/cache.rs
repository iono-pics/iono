use actix_web::http::header::{CacheControl, CacheDirective};
use chrono::{DateTime, Utc};
use iono_core::config::Config;

/// the two ttls, pulled off config at the call site so this stays trivially
/// testable without building a whole Config
#[derive(Clone, Copy)]
pub struct MaxAges {
    pub browser: u32,
    pub edge: u32,
}

impl MaxAges {
    pub fn from_config(config: &Config) -> Self {
        Self {
            browser: config.browser_cache_max_age_seconds,
            edge: config.edge_cache_max_age_seconds,
        }
    }
}

pub fn cache_control(
    ages: MaxAges,
    expires_at: Option<DateTime<Utc>>,
    secret: bool,
) -> CacheControl {
    if secret {
        return CacheControl(vec![CacheDirective::NoStore]);
    }

    let cap = expires_at
        .map(|expires| {
            (expires - Utc::now())
                .num_seconds()
                .clamp(0, ages.edge as i64) as u32
        })
        .unwrap_or(ages.edge);

    CacheControl(vec![
        CacheDirective::Public,
        CacheDirective::MaxAge(ages.browser.min(cap)),
        CacheDirective::SMaxAge(cap),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    const AGES: MaxAges = MaxAges {
        browser: 300,
        edge: 31_536_000,
    };

    fn rendered(cc: CacheControl) -> String {
        use actix_web::http::header::Header;
        let mut res = actix_web::HttpResponse::Ok();
        res.insert_header(cc);
        res.finish()
            .headers()
            .get(actix_web::http::header::CacheControl::name())
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn secret_content_is_never_stored() {
        assert_eq!(rendered(cache_control(AGES, None, true)), "no-store");
        assert_eq!(
            rendered(cache_control(
                AGES,
                Some(Utc::now() + Duration::days(1)),
                true
            )),
            "no-store"
        );
    }

    #[test]
    fn permanent_content_caches_for_a_year_at_the_edge() {
        let cc = rendered(cache_control(AGES, None, false));
        assert!(cc.contains("max-age=300"), "{cc}");
        assert!(cc.contains("s-maxage=31536000"), "{cc}");
    }

    #[test]
    fn caching_never_outlives_the_content() {
        let cc = rendered(cache_control(
            AGES,
            Some(Utc::now() + Duration::seconds(60)),
            false,
        ));

        assert!(
            cc.contains("max-age=59") || cc.contains("max-age=60"),
            "{cc}"
        );
        assert!(
            cc.contains("s-maxage=59") || cc.contains("s-maxage=60"),
            "{cc}"
        );
    }

    #[test]
    fn already_expired_content_is_not_cached() {
        let cc = rendered(cache_control(
            AGES,
            Some(Utc::now() - Duration::days(1)),
            false,
        ));
        assert!(cc.contains("max-age=0"), "{cc}");
        assert!(cc.contains("s-maxage=0"), "{cc}");
    }
}
