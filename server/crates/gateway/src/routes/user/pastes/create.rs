use actix_web::{post, web, HttpResponse};
use chrono::{Duration, Utc};
use iono_core::{
    auth::{password::hash_password_async, token},
    entities::UserSettings,
    web::{append_password_query, ApiResult},
    AppError,
};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{auth::JwtUser, state::AppState};

const MAX_CONTENT_LENGTH: usize = 1024 * 1024;
const MAX_TITLE_LENGTH: usize = 256;
const MAX_SYNTAX_LENGTH: usize = 64;
const MAX_PASSWORD_LENGTH: usize = 256;

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePasteRequest {
    title: Option<String>,
    content: String,
    syntax: Option<String>,
    password: Option<String>,
}

#[utoipa::path(
    post,
    path = "/user/pastes",
    request_body = CreatePasteRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "paste created"),
        (status = 400, description = "invalid paste"),
        (status = 401, description = "missing or invalid token")
    )
)]
#[post("/pastes")]
pub async fn create_paste(
    state: web::Data<AppState>,
    user: JwtUser,
    body: web::Json<CreatePasteRequest>,
) -> ApiResult<HttpResponse> {
    let body = body.into_inner();
    validate(&body)?;

    iono_core::quota::check_storage_quota(&state.db, &user.0.id, body.content.len() as i64).await?;

    let settings =
        sqlx::query_as::<_, UserSettings>("SELECT * FROM user_settings WHERE user_id = $1")
            .bind(&user.0.id)
            .fetch_optional(&state.db)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::internal("user has no settings configured"))?;

    let expires_at = settings
        .default_expires_in_seconds
        .map(|seconds| Utc::now() + Duration::seconds(seconds));
    let password = body.password.filter(|password| !password.is_empty());
    let password_hash = match password.as_ref() {
        Some(password) => Some(hash_password_async(password.clone()).await?),
        None => None,
    };

    let mut paste = None;
    for _ in 0..5 {
        let id = Uuid::new_v4().to_string();
        let key = token::generate_display_name(
            settings.display_name_length as usize,
            &settings.display_name_style,
        );
        paste = sqlx::query_as::<_, (String, String)>(
            r#"
            INSERT INTO pastes (id, user_id, key, title, content, syntax, password_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (key) DO NOTHING
            RETURNING id, key
            "#,
        )
        .bind(id)
        .bind(&user.0.id)
        .bind(key)
        .bind(&body.title)
        .bind(&body.content)
        .bind(&body.syntax)
        .bind(&password_hash)
        .bind(expires_at)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::from)?;

        if paste.is_some() {
            break;
        }
    }

    let (id, key) =
        paste.ok_or_else(|| AppError::internal("failed to generate a unique paste key"))?;

    let (domain, path_prefix) = sqlx::query_as::<_, (String, Option<String>)>(
        r#"
        SELECT d.name, ds.pastes_path_prefix
        FROM domain_settings ds
        INNER JOIN domains d ON d.id = ds.pastes_domain_id
        WHERE ds.user_id = $1
        "#,
    )
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::internal("user has no pastes domain configured"))?;

    let prefix = path_prefix
        .map(|prefix| format!("{prefix}/"))
        .unwrap_or_default();
    let url = append_password_query(
        &format!("https://{domain}/p/{prefix}{key}"),
        password.as_deref(),
    );

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "key": key,
        "url": url,
        "expires_at": expires_at,
    })))
}

fn validate(body: &CreatePasteRequest) -> Result<(), AppError> {
    if body.content.is_empty() {
        return Err(AppError::BadRequest(
            "paste content must not be empty".into(),
        ));
    }
    if body.content.len() > MAX_CONTENT_LENGTH {
        return Err(AppError::BadRequest(
            "paste content must be at most 1 MiB".into(),
        ));
    }
    if body
        .title
        .as_ref()
        .is_some_and(|title| title.chars().count() > MAX_TITLE_LENGTH)
    {
        return Err(AppError::BadRequest(
            "paste title must be at most 256 characters".into(),
        ));
    }
    if body
        .syntax
        .as_ref()
        .is_some_and(|syntax| syntax.chars().count() > MAX_SYNTAX_LENGTH)
    {
        return Err(AppError::BadRequest(
            "paste syntax must be at most 64 characters".into(),
        ));
    }
    if body
        .password
        .as_ref()
        .is_some_and(|password| password.chars().count() > MAX_PASSWORD_LENGTH)
    {
        return Err(AppError::BadRequest(
            "paste password must be at most 256 characters".into(),
        ));
    }
    Ok(())
}
