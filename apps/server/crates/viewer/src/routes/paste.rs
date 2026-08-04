use actix_web::{get, http::header, web, HttpResponse};
use iono_core::{auth::password::verify_password_async, entities::Paste, web::ApiResult, AppError};
use maud::{html, PreEscaped, DOCTYPE};
use serde::Deserialize;

use crate::{cache, csp, state::AppState};

#[derive(Deserialize)]
pub struct PasteQuery {
    password: Option<String>,
}

#[get("/p/{key}")]
pub async fn view_paste(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<PasteQuery>,
) -> ApiResult<HttpResponse> {
    let paste = fetch_paste(&state, &path.into_inner()).await?;
    render_paste(&state, paste, &query).await
}

#[get("/p/{prefix}/{key}")]
pub async fn view_paste_with_prefix(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    query: web::Query<PasteQuery>,
) -> ApiResult<HttpResponse> {
    let (prefix, key) = path.into_inner();
    let paste = fetch_paste_with_prefix(&state, &prefix, &key).await?;
    render_paste(&state, paste, &query).await
}

async fn render_paste(
    state: &AppState,
    paste: Paste,
    query: &PasteQuery,
) -> ApiResult<HttpResponse> {
    if !unlock(&paste, query.password.as_deref()).await? {
        return Err(AppError::NotFound.into());
    }

    let nonce = paste.e2e_encrypted.then(csp::Nonce::new);

    let mut response = HttpResponse::Ok();
    response
        .content_type(header::ContentType::html())
        .append_header((header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .append_header(csp::header(&csp::paste_policy(nonce.as_ref())))
        .append_header(cache::cache_control(
            cache::MaxAges::from_config(&state.config),
            paste.expires_at,
            paste.password_hash.is_some() || paste.e2e_encrypted,
        ));

    Ok(response.body(render_html(&paste, nonce.as_ref())))
}

async fn fetch_paste(state: &AppState, key: &str) -> Result<Paste, AppError> {
    sqlx::query_as::<_, Paste>(
        r#"
        SELECT p.* FROM pastes p
        INNER JOIN users u ON u.id = p.user_id
        LEFT JOIN domain_settings ds ON ds.user_id = p.user_id
        WHERE p.key = $1
          AND ds.pastes_path_prefix IS NULL
          AND (p.expires_at IS NULL OR p.expires_at > now())
          AND u.deleted_at IS NULL
        "#,
    )
    .bind(key)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::NotFound)
}

async fn fetch_paste_with_prefix(
    state: &AppState,
    prefix: &str,
    key: &str,
) -> Result<Paste, AppError> {
    sqlx::query_as::<_, Paste>(
        r#"
        SELECT p.* FROM pastes p
        INNER JOIN domain_settings ds ON ds.user_id = p.user_id
        INNER JOIN users u ON u.id = p.user_id
        WHERE p.key = $1
          AND ds.pastes_path_prefix = $2
          AND (p.expires_at IS NULL OR p.expires_at > now())
          AND u.deleted_at IS NULL
        "#,
    )
    .bind(key)
    .bind(prefix)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::NotFound)
}

async fn unlock(paste: &Paste, password: Option<&str>) -> Result<bool, AppError> {
    let Some(hash) = paste.password_hash.clone() else {
        return Ok(true);
    };
    let Some(password) = password.map(str::to_owned) else {
        return Ok(false);
    };

    verify_password_async(password, hash).await
}

fn render_html(paste: &Paste, nonce: Option<&csp::Nonce>) -> String {
    let title = paste.title.as_deref().unwrap_or("Paste");
    let syntax = paste.syntax.as_deref().unwrap_or("plain text");
    let created_at = paste.created_at.format("%B %-d, %Y at %H:%M UTC");

    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                meta property="og:title" content=(title);
            }
            body {
                main {
                    header {
                        h1 { (title) }
                        p {
                            (syntax) " / " (created_at)
                            @if paste.e2e_encrypted { " / end-to-end encrypted" }
                        }
                    }
                    @if paste.e2e_encrypted {
                        pre id="content" data-ciphertext=(&paste.content) {
                            code { "Decrypting…" }
                        }
                        script nonce=[nonce.map(csp::Nonce::value)] { (PreEscaped(DECRYPT_JS)) }
                        noscript { p { "Please enable javascript for decryption" } }
                    } @else {
                        pre { code { (&paste.content) } }
                    }
                }
            }
        }
    }
    .into_string()
}

const DECRYPT_JS: &str = r#"
(async () => {
  const el = document.getElementById('content');
  const out = el.querySelector('code');
  const fail = (msg) => { out.textContent = msg; };

  const b64 = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

  const keyText = location.hash.slice(1);
  if (!keyText) return fail('This paste is encrypted');

  try {
    const raw = b64(keyText);
    const payload = b64(el.dataset.ciphertext);
    const iv = payload.slice(0, 12);
    const data = payload.slice(12);
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    out.textContent = new TextDecoder().decode(plain);
  } catch (e) {
    fail('Could not decrypt this paste');
  }
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn escapes_paste_content_and_title() {
        let paste = Paste {
            id: "p1".into(),
            user_id: "u1".into(),
            key: "abc".into(),
            title: Some("<script>title</script>".into()),
            content: "<script>alert(1)</script>".into(),
            syntax: None,
            password_hash: None,
            expires_at: None,
            e2e_encrypted: false,
            created_at: Utc::now(),
        };

        let html = render_html(&paste, None);
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }
}
