use actix_web::{patch, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{
    auth::password::hash_password_async,
    entities::Paste,
    validators,
    web::{ApiResult, OptionExt, Patch},
    AppError,
};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{auth::AuthedUser, routes::user::pastes::list::PasteSummary, state::AppState};

const MAX_CONTENT_LENGTH: usize = 1024 * 1024;

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct UpdatePasteRequest {
    #[schema(value_type = Option<String>)]
    title: Patch<String>,
    content: Option<String>,
    #[schema(value_type = Option<String>)]
    syntax: Patch<String>,
    #[schema(value_type = Option<String>)]
    password: Patch<String>,
    #[schema(value_type = Option<DateTime<Utc>>)]
    expires_at: Patch<DateTime<Utc>>,
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

    if !body.title.is_provided()
        && body.content.is_none()
        && !body.syntax.is_provided()
        && !body.password.is_provided()
        && !body.expires_at.is_provided()
    {
        return Err(AppError::BadRequest("no fields to update".into()).into());
    }

    let paste_id = path.into_inner();

    if let Some(new_content) = &body.content {
        let old_len: i64 = sqlx::query_scalar(
            "SELECT octet_length(content) FROM pastes WHERE id = $1 AND user_id = $2",
        )
        .bind(&paste_id)
        .bind(&user.0.id)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::from)?
        .ok_or_not_found()?;

        let delta = new_content.len() as i64 - old_len;
        if delta > 0 {
            iono_core::quota::check_storage_quota(&state.db, &user.0.id, delta).await?;
        }
    }

    let (title_provided, title_value) = body.title.split();
    let (syntax_provided, syntax_value) = body.syntax.split();
    let (expires_provided, expires_value) = body.expires_at.split();
    let (password_provided, password_plain) = body.password.split();
    let password_hash: Option<String> = match password_plain {
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

    let paste = updated.ok_or_not_found()?;

    let content_or_password_changed = body.content.is_some() || password_provided;
    if content_or_password_changed && state.cloudflare.is_configured() {
        if let Some(url) = iono_core::urls::paste_url(&state.db, &user.0.id, &paste.key).await? {
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

fn validate(body: &UpdatePasteRequest) -> Result<(), AppError> {
    if let Some(content) = &body.content {
        if content.is_empty() {
            return Err(AppError::BadRequest("content must not be empty".into()));
        }
        if content.len() > MAX_CONTENT_LENGTH {
            return Err(AppError::BadRequest("content must be at most 1 MiB".into()));
        }
    }

    if let Some(title) = body.title.as_set() {
        validators::text_length(title, 256, "title")?;
    }

    if let Some(syntax) = body.syntax.as_set() {
        validators::text_length(syntax, 64, "syntax")?;
    }

    if let Some(password) = body.password.as_set() {
        validators::password(password, 256)?;
    }

    if let Some(at) = body.expires_at.as_set() {
        validators::future_datetime(*at)?;
    }

    Ok(())
}
