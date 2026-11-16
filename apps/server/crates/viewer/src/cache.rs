use actix_web::http::header::{CacheControl, CacheDirective};
use chrono::{DateTime, Utc};
use iono_core::config::Config;
use iono_core::deletion;

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

/// lets deletion purge every cached copy by id or by owner. the worker strips
/// it before the response leaves the edge
pub fn file_tags(file_id: &str, user_id: &str) -> (&'static str, String) {
    (
        "Cache-Tag",
        format!(
            "{},{}",
            deletion::file_tag(file_id),
            deletion::user_tag(user_id)
        ),
    )
}

pub fn paste_tags(paste_id: &str, user_id: &str) -> (&'static str, String) {
    (
        "Cache-Tag",
        format!(
            "{},{}",
            deletion::paste_tag(paste_id),
            deletion::user_tag(user_id)
        ),
    )
}

pub fn cache_control(
    ages: MaxAges,
    expires_at: Option<DateTime<Utc>>,
    secret: bool,
) -> CacheControl {
    if secret {
        return CacheControl(vec![CacheDirective::NoStore]);
    }

    let cap = expires_at.map_or(ages.edge, |expires| {
        let left = (expires - Utc::now())
            .num_seconds()
            .clamp(0, i64::from(ages.edge));
        u32::try_from(left).unwrap_or(ages.edge)
    });

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
    fn tags_name_the_resource_and_its_owner() {
        assert_eq!(file_tags("f1", "u1").1, "file-f1,user-u1");
        assert_eq!(paste_tags("p1", "u1").1, "paste-p1,user-u1");
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
