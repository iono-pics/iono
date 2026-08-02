use actix_web::{patch, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{auth::password::hash_password_async, entities::Paste, web::ApiResult, AppError};
use serde::{Deserialize, Deserializer};
use utoipa::ToSchema;

use crate::{auth::AuthedUser, routes::user::pastes::list::PasteSummary, state::AppState};

const MAX_CONTENT_LENGTH: usize = 1024 * 1024;
const MAX_TITLE_LENGTH: usize = 256;
const MAX_SYNTAX_LENGTH: usize = 64;
const MAX_PASSWORD_LENGTH: usize = 256;

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct UpdatePasteRequest {
    #[serde(default, deserialize_with = "deserialize_some")]
    title: Option<Option<String>>,
    content: Option<String>,
    #[serde(default, deserialize_with = "deserialize_some")]
    syntax: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    password: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    expires_at: Option<Option<DateTime<Utc>>>,
}

fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[utoipa::path(
    patch,
    path = "/user/pastes/{id}",
    request_body = UpdatePasteRequest,
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "paste id")),
    responses(
        (status = 200, description = "paste updated", body = PasteSummary),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing or invalid token"),
        (status = 402, description = "storage quota exceeded"),
        (status = 404, description = "no such paste"),
    )
)]
#[patch("/pastes/{id}")]
pub async fn update_paste(
    state: web::Data<AppState>,
    user: AuthedUser,
    path: web::Path<String>,
    body: web::Json<UpdatePasteRequest>,
) -> ApiResult<HttpResponse> {
    let body = body.into_inner();
    validate(&body)?;

    if body.title.is_none()
        && body.content.is_none()
        && body.syntax.is_none()
        && body.password.is_none()
        && body.expires_at.is_none()
    {
        return Err(AppError::BadRequest("no fields to update".into()).into());
    }

    let paste_id = path.into_inner();

    if let Some(new_content) = &body.content {
        let old_len: Option<i64> = sqlx::query_scalar(
            "SELECT octet_length(content) FROM pastes WHERE id = $1 AND user_id = $2",
        )
        .bind(&paste_id)
        .bind(&user.0.id)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::from)?;

        let Some(old_len) = old_len else {
            return Err(AppError::NotFound.into());
        };

        let delta = new_content.len() as i64 - old_len;
        if delta > 0 {
            iono_core::quota::check_storage_quota(&state.db, &user.0.id, delta).await?;
        }
    }

    let title_provided = body.title.is_some();
    let title_value = body.title.flatten();

    let syntax_provided = body.syntax.is_some();
    let syntax_value = body.syntax.flatten();

    let expires_provided = body.expires_at.is_some();
    let expires_value = body.expires_at.flatten();

    let password_provided = body.password.is_some();
    let password_hash: Option<String> = match body.password.flatten() {
        Some(pw) => Some(hash_password_async(pw).await?),
        None => None,
    };

    let updated = sqlx::query_as::<_, Paste>(
        r#"
        UPDATE pastes SET
            title         = CASE WHEN $1  THEN $2  ELSE title END,
            content       = COALESCE($3, content),
            syntax        = CASE WHEN $4  THEN $5  ELSE syntax END,
            password_hash = CASE WHEN $6  THEN $7  ELSE password_hash END,
            expires_at    = CASE WHEN $8  THEN $9  ELSE expires_at END
        WHERE id = $10 AND user_id = $11
        RETURNING *
        "#,
    )
    .bind(title_provided)
    .bind(&title_value)
    .bind(&body.content)
    .bind(syntax_provided)
    .bind(&syntax_value)
    .bind(password_provided)
    .bind(&password_hash)
    .bind(expires_provided)
    .bind(expires_value)
    .bind(&paste_id)
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?;

    let Some(paste) = updated else {
        return Err(AppError::NotFound.into());
    };

    let content_or_password_changed = body.content.is_some() || password_provided;
    if content_or_password_changed {
        if let Some(url) = paste_url(&state, &user.0.id, &paste.key).await? {
            let cf = state.cloudflare.clone();
            let paste_id = paste.id.clone();
            tokio::spawn(async move {
                if let Err(e) = cf.purge_urls(vec![url]).await {
                    tracing::warn!(paste_id = %paste_id, error = %e, "cloudflare purge failed");
                }
            });
        }
    }

    Ok(HttpResponse::Ok().json(PasteSummary::from(paste)))
}

async fn paste_url(state: &AppState, user_id: &str, key: &str) -> Result<Option<String>, AppError> {
    if !state.cloudflare.is_configured() {
        return Ok(None);
    }
    let domain: Option<(String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT d.name, ds.pastes_path_prefix
        FROM domain_settings ds
        INNER JOIN domains d ON d.id = ds.pastes_domain_id
        WHERE ds.user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?;

    Ok(domain.map(|(host, prefix)| {
        let prefix = prefix.map(|p| format!("{p}/")).unwrap_or_default();
        format!("https://{host}/p/{prefix}{key}")
    }))
}

fn validate(body: &UpdatePasteRequest) -> Result<(), AppError> {
    if let Some(content) = &body.content {
        if content.is_empty() {
            return Err(AppError::BadRequest("content must not be empty".into()));
        }
        if content.len() > MAX_CONTENT_LENGTH {
            return Err(AppError::BadRequest("content must be at most 1 MiB".into()));
        }
    }

    if let Some(Some(title)) = &body.title {
        if title.chars().count() > MAX_TITLE_LENGTH {
            return Err(AppError::BadRequest(format!(
                "title must be at most {MAX_TITLE_LENGTH} characters"
            )));
        }
    }

    if let Some(Some(syntax)) = &body.syntax {
        if syntax.chars().count() > MAX_SYNTAX_LENGTH {
            return Err(AppError::BadRequest(format!(
                "syntax must be at most {MAX_SYNTAX_LENGTH} characters"
            )));
        }
    }

    if let Some(Some(password)) = &body.password {
        if password.is_empty() || password.chars().count() > MAX_PASSWORD_LENGTH {
            return Err(AppError::BadRequest(format!(
                "password must be 1-{MAX_PASSWORD_LENGTH} characters, or null to clear"
            )));
        }
    }

    if let Some(Some(at)) = body.expires_at {
        if at <= Utc::now() {
            return Err(AppError::BadRequest(
                "expires_at must be in the future".into(),
            ));
        }
    }

    Ok(())
}
