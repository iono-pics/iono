//! chunked uploads. the edge caps one request body at 100MB on most plans, so
//! anything bigger is sent as fixed size parts that each become one part of an
//! s3 multipart upload. every part is encrypted at its own byte offset, so the
//! stored object is identical to what a single streamed upload would write

use actix_web::{delete, post, put, web, HttpResponse};
use chrono::{DateTime, Duration, Utc};
use futures_util::StreamExt;
use iono_core::{content_type, crypto, quota, AppError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;

use iono_core::web::ApiResult;

use crate::{
    auth::ApiKeyUser,
    routes::upload::{finalize, user_settings, Budget, Uploaded, UserKey, SNIFF_BYTES},
    state::AppState,
};

/// comfortably under the edge body limit, and r2 wants every part but the
/// last to be the same size
pub const PART_SIZE: i64 = 16 * 1024 * 1024;
// a part must end on a segment boundary to be sealed on its own
const _: () = assert!((PART_SIZE as usize).is_multiple_of(crypto::SEGMENT_LEN));
const SESSION_TTL_HOURS: i64 = 24;
// objects are ciphertext, the real type lives on the files row
const OBJECT_CONTENT_TYPE: &str = "application/octet-stream";

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUploadSessionRequest {
    /// total size of the file in bytes
    size: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UploadSessionResponse {
    id: String,
    part_size: i64,
    part_count: i64,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct CompleteUploadSessionRequest {
    password: Option<String>,
}

#[derive(sqlx::FromRow)]
struct Session {
    id: String,
    s3_key: String,
    s3_upload_id: String,
    size_bytes: i64,
    part_size_bytes: i64,
    content_type: Option<String>,
    parts: sqlx::types::Json<HashMap<String, String>>,
    encryption_key_version: i16,
    encryption_iv: Vec<u8>,
    wrapped_dek: Vec<u8>,
    dek_iv: Vec<u8>,
    wrapped_user_key: Option<Vec<u8>>,
    user_key_wrap_iv: Option<Vec<u8>>,
}

impl Session {
    fn part_count(&self) -> i64 {
        part_count(self.size_bytes, self.part_size_bytes)
    }

    fn expected_part_len(&self, part_number: i64) -> i64 {
        let start = (part_number - 1) * self.part_size_bytes;
        self.part_size_bytes.min(self.size_bytes - start)
    }

    fn dek(&self, state: &AppState) -> Result<[u8; crypto::KEY_LEN], AppError> {
        let kek = state.keyring.get(self.encryption_key_version)?;
        crypto::open_key(kek, &self.dek_iv, &self.wrapped_dek, &dek_aad(&self.id))
    }

    fn user_key(&self, state: &AppState) -> Result<Option<UserKey>, AppError> {
        let (Some(wrapped), Some(nonce)) = (
            self.wrapped_user_key.as_deref(),
            self.user_key_wrap_iv.as_deref(),
        ) else {
            return Ok(None);
        };
        let kek = state.keyring.get(self.encryption_key_version)?;
        crypto::open_key(kek, nonce, wrapped, &user_key_aad(&self.id)).map(Some)
    }

    fn content_key(&self, state: &AppState) -> Result<[u8; crypto::KEY_LEN], AppError> {
        Ok(crypto::content_key(
            &self.dek(state)?,
            &self.encryption_iv,
            self.user_key(state)?.as_ref(),
        ))
    }
}

// keys wait here between requests, bound to this session so they open nowhere else
fn dek_aad(session_id: &str) -> Vec<u8> {
    [b"iono session dek\0".as_slice(), session_id.as_bytes()].concat()
}

fn user_key_aad(session_id: &str) -> Vec<u8> {
    [b"iono session user key\0".as_slice(), session_id.as_bytes()].concat()
}

async fn check_budget(
    state: &AppState,
    db: &mut sqlx::PgConnection,
    user_id: &str,
    size: i64,
) -> Result<(), AppError> {
    let plan = quota::plan_for_user(&mut *db, user_id).await?;
    let used = quota::storage_used_bytes(&mut *db, user_id).await?;
    let budget = Budget::new(&plan, used, state.config.max_upload_size_bytes);
    if size as u64 > budget.limit {
        return Err(budget.exceeded());
    }
    Ok(())
}

fn part_count(size: i64, part_size: i64) -> i64 {
    (size + part_size - 1) / part_size
}

fn iv(bytes: &[u8]) -> Result<[u8; crypto::IV_LEN], AppError> {
    bytes
        .try_into()
        .map_err(|_| AppError::internal("stored upload session iv is malformed"))
}

/// the same rules a single streamed upload follows. image signatures are only
/// trusted when the whole image decodes, which needs the whole file in part 1
fn sniff(first_part: &[u8], is_whole_file: bool, decode_limit: usize) -> String {
    if content_type::needs_whole_body(first_part) {
        if is_whole_file && first_part.len() <= decode_limit {
            content_type::detect(first_part)
        } else {
            content_type::FALLBACK_MIME_TYPE.to_string()
        }
    } else {
        content_type::detect(&first_part[..first_part.len().min(SNIFF_BYTES)])
    }
}

async fn fetch_session(state: &AppState, user_id: &str, id: &str) -> Result<Session, AppError> {
    sqlx::query_as::<_, Session>(
        "SELECT * FROM upload_sessions WHERE id = $1 AND user_id = $2 AND expires_at > now()",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::NotFound)
}

#[utoipa::path(
    post,
    path = "/uploads",
    request_body = CreateUploadSessionRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "session created, send parts of part_size bytes", body = UploadSessionResponse),
        (status = 400, description = "invalid size"),
        (status = 401, description = "missing or invalid api key"),
        (status = 402, description = "plan size or storage quota exceeded"),
        (status = 413, description = "file exceeds the server upload limit")
    )
)]
#[post("/uploads")]
pub async fn create_upload_session(
    state: web::Data<AppState>,
    user: ApiKeyUser,
    body: web::Json<CreateUploadSessionRequest>,
) -> ApiResult<HttpResponse> {
    if body.size <= 0 {
        return Err(AppError::BadRequest("size must be positive".into()).into());
    }

    let settings = user_settings(&state, &user.0.id).await?;
    // a cheap early no before touching storage. the locked check below,
    // made with the session insert, is the one that counts
    let mut conn = state.db.acquire().await.map_err(AppError::from)?;
    check_budget(&state, &mut conn, &user.0.id, body.size).await?;
    drop(conn);

    let id = Uuid::new_v4().to_string();
    let kek = state.keyring.current();
    let (wrapped_dek, dek_iv) = crypto::seal_key(kek, &crypto::random_key(), &dek_aad(&id))?;
    let (wrapped_user_key, user_key_wrap_iv) = if settings.encrypt_uploads {
        let (wrapped, nonce) = crypto::seal_key(kek, &crypto::random_key(), &user_key_aad(&id))?;
        (Some(wrapped), Some(nonce))
    } else {
        (None, None)
    };

    let s3_key = format!("{}.bin", Uuid::new_v4());
    let upload_id = state
        .storage
        .begin_multipart(&s3_key, OBJECT_CONTENT_TYPE)
        .await?;
    let expires_at = Utc::now() + Duration::hours(SESSION_TTL_HOURS);

    // the session row is the quota claim, its size counts as used until it
    // completes or expires
    let mut tx = state.db.begin().await.map_err(AppError::from)?;
    let claimed = async {
        quota::lock_user(&mut tx, &user.0.id).await?;
        check_budget(&state, &mut tx, &user.0.id, body.size).await?;
        sqlx::query(
        r#"
        INSERT INTO upload_sessions (id, user_id, s3_key, s3_upload_id, size_bytes, part_size_bytes, encryption_key_version, encryption_iv, wrapped_dek, dek_iv, wrapped_user_key, user_key_wrap_iv, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        "#,
    )
    .bind(&id)
    .bind(&user.0.id)
    .bind(&s3_key)
    .bind(&upload_id)
    .bind(body.size)
    .bind(PART_SIZE)
    .bind(state.keyring.current_version())
    .bind(crypto::random_iv().to_vec())
    .bind(wrapped_dek)
    .bind(dek_iv)
    .bind(wrapped_user_key)
    .bind(user_key_wrap_iv)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
        Ok::<_, AppError>(())
    }
    .await;
    let claimed = match claimed {
        Ok(()) => tx.commit().await.map_err(AppError::from),
        Err(e) => Err(e),
    };

    if let Err(e) = claimed {
        if let Err(abort) = state.storage.abort_multipart(&s3_key, &upload_id).await {
            tracing::warn!(s3_key = %s3_key, error = %abort, "could not abort multipart upload");
        }
        return Err(e.into());
    }

    Ok(HttpResponse::Created().json(UploadSessionResponse {
        id,
        part_size: PART_SIZE,
        part_count: part_count(body.size, PART_SIZE),
        expires_at,
    }))
}

#[utoipa::path(
    put,
    path = "/uploads/{id}/parts/{part_number}",
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "upload session id"),
        ("part_number" = i64, Path, description = "1-based part number"),
    ),
    responses(
        (status = 204, description = "part stored, resending a part replaces it"),
        (status = 400, description = "part number out of range or wrong length"),
        (status = 401, description = "missing or invalid api key"),
        (status = 404, description = "no such session, or it expired")
    )
)]
#[put("/uploads/{id}/parts/{part_number}")]
pub async fn upload_part(
    state: web::Data<AppState>,
    user: ApiKeyUser,
    path: web::Path<(String, i64)>,
    mut payload: web::Payload,
) -> ApiResult<HttpResponse> {
    let (id, part_number) = path.into_inner();
    let session = fetch_session(&state, &user.0.id, &id).await?;

    if part_number < 1 || part_number > session.part_count() {
        return Err(AppError::BadRequest(format!(
            "part number must be between 1 and {}",
            session.part_count()
        ))
        .into());
    }

    let expected = session.expected_part_len(part_number) as usize;
    let mut buf = Vec::with_capacity(expected);
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|e| AppError::BadRequest(format!("malformed body: {e}")))?;
        if buf.len() + chunk.len() > expected {
            return Err(AppError::BadRequest(format!(
                "part {part_number} must be {expected} bytes"
            ))
            .into());
        }
        buf.extend_from_slice(&chunk);
    }
    if buf.len() != expected {
        return Err(
            AppError::BadRequest(format!("part {part_number} must be {expected} bytes")).into(),
        );
    }

    let sniffed = (part_number == 1).then(|| {
        sniff(
            &buf,
            session.part_count() == 1,
            state.config.max_image_decode_bytes,
        )
    });

    // every part seals its own run of segments, and only the final part's
    // last segment carries the end of file flag
    let first_segment =
        ((part_number - 1) * session.part_size_bytes) as u64 / crypto::SEGMENT_LEN as u64;
    let mut sealer = crypto::Sealer::starting_at(&session.content_key(&state)?, first_segment);
    let mut sealed = sealer.push(&buf)?;
    sealed.extend(if part_number == session.part_count() {
        sealer.finish()?
    } else {
        sealer.finish_not_last()?
    });
    drop(buf);

    let etag = state
        .storage
        .put_part(
            &session.s3_key,
            &session.s3_upload_id,
            part_number as i32,
            sealed,
        )
        .await?;

    sqlx::query(
        r#"
        UPDATE upload_sessions
        SET parts = parts || jsonb_build_object($3::text, $4::text),
            content_type = COALESCE($5, content_type)
        WHERE id = $1 AND user_id = $2
        "#,
    )
    .bind(&id)
    .bind(&user.0.id)
    .bind(part_number.to_string())
    .bind(etag)
    .bind(sniffed)
    .execute(&state.db)
    .await
    .map_err(AppError::from)?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    post,
    path = "/uploads/{id}/complete",
    request_body = CompleteUploadSessionRequest,
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "upload session id")),
    responses(
        (status = 201, description = "file created"),
        (status = 400, description = "parts are missing, or an invalid password"),
        (status = 401, description = "missing or invalid api key"),
        (status = 402, description = "storage quota exceeded while uploading"),
        (status = 404, description = "no such session, or it expired")
    )
)]
#[post("/uploads/{id}/complete")]
pub async fn complete_upload_session(
    state: web::Data<AppState>,
    user: ApiKeyUser,
    path: web::Path<String>,
    body: Option<web::Json<CompleteUploadSessionRequest>>,
) -> ApiResult<HttpResponse> {
    let id = path.into_inner();
    let body = body.map(web::Json::into_inner).unwrap_or_default();

    // the row lock makes a double complete wait, then find no session
    let mut tx = state.db.begin().await.map_err(AppError::from)?;
    let session = sqlx::query_as::<_, Session>(
        r#"
        SELECT * FROM upload_sessions
        WHERE id = $1 AND user_id = $2 AND expires_at > now()
        FOR UPDATE
        "#,
    )
    .bind(&id)
    .bind(&user.0.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::NotFound)?;

    let mut parts = Vec::with_capacity(session.part_count() as usize);
    let mut missing = Vec::new();
    for number in 1..=session.part_count() {
        match session.parts.get(&number.to_string()) {
            Some(etag) => parts.push((number as i32, etag.clone())),
            None => missing.push(number),
        }
    }
    if !missing.is_empty() {
        return Err(
            AppError::BadRequest(format!("parts {missing:?} have not been uploaded")).into(),
        );
    }

    // no quota check here, the session has counted against it since creation
    let settings = user_settings(&state, &user.0.id).await?;

    state
        .storage
        .complete_multipart(&session.s3_key, &session.s3_upload_id, parts)
        .await?;

    let uploaded = Uploaded {
        mime_type: session
            .content_type
            .clone()
            .unwrap_or_else(|| content_type::FALLBACK_MIME_TYPE.to_string()),
        size_bytes: session.size_bytes,
        encryption_iv: iv(&session.encryption_iv)?,
        dek: session.dek(&state)?,
        user_key: session.user_key(&state)?,
        s3_key: session.s3_key,
    };
    let url = finalize(&state, &user.0.id, &settings, uploaded, body.password, None).await?;

    sqlx::query("DELETE FROM upload_sessions WHERE id = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;
    tx.commit().await.map_err(AppError::from)?;

    Ok(HttpResponse::Created().json(serde_json::json!({ "url": url })))
}

#[utoipa::path(
    delete,
    path = "/uploads/{id}",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "upload session id")),
    responses(
        (status = 204, description = "session and its parts discarded"),
        (status = 404, description = "no such session")
    )
)]
#[delete("/uploads/{id}")]
pub async fn abort_upload_session(
    state: web::Data<AppState>,
    user: ApiKeyUser,
    path: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let (s3_key, upload_id) = sqlx::query_as::<_, (String, String)>(
        "DELETE FROM upload_sessions WHERE id = $1 AND user_id = $2 RETURNING s3_key, s3_upload_id",
    )
    .bind(path.into_inner())
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::NotFound)?;

    if let Err(e) = state.storage.abort_multipart(&s3_key, &upload_id).await {
        tracing::warn!(s3_key = %s3_key, error = %e, "could not abort multipart upload");
    }

    Ok(HttpResponse::NoContent().finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(side: u32) -> Vec<u8> {
        let img = image::RgbImage::new(side, side);
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .unwrap();
        bytes
    }

    #[test]
    fn part_count_rounds_up() {
        assert_eq!(part_count(1, PART_SIZE), 1);
        assert_eq!(part_count(PART_SIZE, PART_SIZE), 1);
        assert_eq!(part_count(PART_SIZE + 1, PART_SIZE), 2);
        assert_eq!(part_count(10 * 1024 * 1024 * 1024, PART_SIZE), 640);
    }

    #[test]
    fn a_ten_gigabyte_file_fits_in_the_s3_part_limit() {
        assert!(part_count(10 * 1024 * 1024 * 1024, PART_SIZE) <= 10_000);
    }

    #[test]
    fn a_whole_image_in_part_one_is_recognised() {
        assert_eq!(sniff(&png(8), true, 32 * 1024 * 1024), "image/png");
    }

    #[test]
    fn an_image_split_across_parts_is_not_trusted() {
        assert_eq!(
            sniff(&png(8), false, 32 * 1024 * 1024),
            content_type::FALLBACK_MIME_TYPE
        );
    }

    #[test]
    fn an_image_over_the_decode_limit_is_not_trusted() {
        let image = png(8);
        assert_eq!(
            sniff(&image, true, image.len() - 1),
            content_type::FALLBACK_MIME_TYPE
        );
    }
}
