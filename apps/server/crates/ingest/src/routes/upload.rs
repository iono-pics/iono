use actix_multipart::{Field, Multipart};
use actix_web::{http::header, post, web, HttpRequest, HttpResponse};
use bytes::Bytes;
use chrono::{Duration, Utc};
use futures_util::{stream, TryStreamExt};
use iono_core::{
    auth::{
        password::{hash_password_async, hash_secret},
        token,
    },
    content_type, crypto,
    entities::{File, Plan, UserSettings},
    image_compress, quota, validators, AppError,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::mpsc;
use utoipa::ToSchema;
use uuid::Uuid;

use iono_core::web::{append_query, ApiResult};

use crate::{auth::ApiKeyUser, state::AppState};

pub(crate) const SNIFF_BYTES: usize = 8192;
// one request through the edge is at most a few hundred MB
const RESERVATION_TTL: Duration = Duration::hours(1);
const MAX_TEXT_FIELD_BYTES: usize = 8192;
const MAX_FORM_FIELDS: usize = 8;
// longest the client may go without sending the next chunk
const BODY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const CHANNEL_DEPTH: usize = 4;
const PUMP_CHUNK: usize = 256 * 1024;

#[derive(ToSchema)]
pub struct UploadForm {
    #[schema(value_type = String, format = Binary)]
    #[allow(dead_code)]
    file: Vec<u8>,
    #[schema(value_type = Option<String>)]
    #[allow(dead_code)]
    password: Option<String>,
}

#[utoipa::path(
    post,
    path = "/",
    request_body(content = UploadForm, content_type = "multipart/form-data"),
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "file uploaded"),
        (status = 400, description = "missing or malformed file, or an invalid password"),
        (status = 401, description = "missing or invalid api key"),
        (status = 402, description = "plan size or storage quota exceeded"),
        (status = 413, description = "file exceeded the server upload limit"),
        (status = 415, description = "body was not multipart/form-data")
    )
)]
#[post("/")]
pub async fn upload_file(
    state: web::Data<AppState>,
    user: ApiKeyUser,
    req: HttpRequest,
    mut payload: Multipart,
) -> ApiResult<HttpResponse> {
    let settings = user_settings(&state, &user.0.id).await?;

    // claimed before a byte is read, so concurrent uploads see each other.
    // the declared length bounds the claim, the stream is held to it below
    let declared = declared_length(&req);
    let cap = state.config.max_upload_size_bytes;
    let mut decided = None;
    let reservation = quota::reserve(&state.db, &user.0.id, RESERVATION_TTL, |plan, used| {
        let budget = Budget::new(plan, used, cap);
        let wanted = declared.unwrap_or(budget.limit);
        let claim = if wanted > budget.limit {
            Err(budget.exceeded())
        } else {
            Ok(wanted as i64)
        };
        decided = Some(budget);
        claim
    })
    .await?;
    let mut budget = decided.ok_or_else(|| AppError::internal("quota was not decided"))?;
    budget.limit = reservation.bytes as u64;

    let mut plain_password: Option<String> = None;
    let mut uploaded: Option<Uploaded> = None;

    let mut field_count = 0usize;
    while let Some(field) = within_idle_timeout(payload.try_next()).await? {
        field_count += 1;
        if field_count > MAX_FORM_FIELDS {
            return Err(AppError::BadRequest("too many form fields".into()).into());
        }
        match field.name() {
            Some("password") => {
                let text = read_text_field(field).await?;
                plain_password = Some(text).filter(|p| !p.is_empty());
            }
            Some("file") if uploaded.is_none() => {
                uploaded = Some(
                    store_field(
                        &state,
                        field,
                        &budget,
                        settings.encrypt_uploads,
                        settings.lossless_images,
                    )
                    .await?,
                );
            }
            _ => drain_field(field).await?,
        }
    }

    let Some(uploaded) = uploaded else {
        return Err(AppError::BadRequest("missing file".into()).into());
    };

    let url = finalize(
        &state,
        &user.0.id,
        &settings,
        uploaded,
        plain_password,
        Some(reservation),
    )
    .await?;
    Ok(HttpResponse::Created().json(serde_json::json!({ "url": url })))
}

pub(crate) async fn user_settings(
    state: &AppState,
    user_id: &str,
) -> Result<UserSettings, AppError> {
    sqlx::query_as::<_, UserSettings>("SELECT * FROM user_settings WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::internal("user has no settings configured"))
}

/// writes the files row for an object already in storage and builds its share url
pub(crate) async fn finalize(
    state: &AppState,
    user_id: &str,
    settings: &UserSettings,
    uploaded: Uploaded,
    plain_password: Option<String>,
    reservation: Option<quota::Reservation>,
) -> Result<String, AppError> {
    if let Some(password) = plain_password.as_deref() {
        validators::password(password, 256)?;
    }
    let password_hash = match plain_password.clone() {
        Some(p) => Some(hash_password_async(p).await?),
        None => None,
    };

    let (user_key, user_key_hash) = match uploaded.user_key {
        Some(key) => {
            let encoded = crypto::encode_key(&key);
            let hash = hash_secret(&encoded);
            (Some(encoded), Some(hash))
        }
        None => (None, None),
    };

    let id = Uuid::new_v4().to_string();
    let (wrapped_dek, dek_iv) = crypto::seal_key(
        state.keyring.current(),
        &uploaded.dek,
        &crypto::file_key_aad(&id),
    )?;
    let encryption_key_version = state.keyring.current_version();

    let expires_at = settings
        .default_expires_in_seconds
        .map(|secs| Utc::now() + Duration::seconds(secs));

    let extension = content_type::extension_for(&uploaded.mime_type);
    let display_name_stem = token::generate_display_name(
        settings.display_name_length as usize,
        &settings.display_name_style,
    );
    let display_name = if settings.display_name_include_extension {
        format!("{display_name_stem}.{extension}")
    } else {
        display_name_stem
    };

    let db = state.db.clone();
    let owner_id = user_id.to_owned();
    let Uploaded {
        s3_key,
        mime_type,
        size_bytes,
        encryption_iv,
        ..
    } = uploaded;

    // detached so a client disconnecting cant orphan the object we just wrote.
    // the claim on quota becomes the row in one step
    let finalize = tokio::spawn(async move {
        let mut tx = db.begin().await?;
        let file = sqlx::query_as::<_, File>(
            r#"
            INSERT INTO files (id, user_id, display_name, original_name, content_type, size_bytes, password_hash, expires_at, encrypted, encryption_iv, user_key_hash, encryption_key_version, wrapped_dek, dek_iv, encryption_format)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&owner_id)
        .bind(&display_name)
        .bind(&s3_key)
        .bind(&mime_type)
        .bind(size_bytes)
        .bind(&password_hash)
        .bind(expires_at)
        .bind(user_key_hash.is_some())
        .bind(encryption_iv.to_vec())
        .bind(&user_key_hash)
        .bind(encryption_key_version)
        .bind(&wrapped_dek)
        .bind(&dek_iv)
        .bind(crypto::FORMAT_SEGMENTED_GCM)
        .fetch_one(&mut *tx)
        .await?;
        if let Some(reservation) = reservation {
            reservation.settle(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok::<_, AppError>(file)
    });

    let file = finalize
        .await
        .map_err(|e| AppError::internal_from("upload finalize panicked", e))??;

    let (files_domain, files_path_prefix) = sqlx::query_as::<_, (String, Option<String>)>(
        r#"
        SELECT d.name, ds.files_path_prefix
        FROM domain_settings ds
        INNER JOIN domains d ON d.id = ds.files_domain_id
        WHERE ds.user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::internal("user has no files domain configured"))?;

    let prefix = files_path_prefix
        .map(|p| format!("{p}/"))
        .unwrap_or_default();

    let base_url = if settings.raw_links_only {
        format!("https://{files_domain}/{prefix}raw/{}", file.display_name)
    } else {
        format!("https://{files_domain}/{prefix}{}", file.display_name)
    };

    Ok(append_query(
        &base_url,
        &[
            ("password", plain_password.as_deref()),
            ("key", user_key.as_deref()),
        ],
    ))
}

pub(crate) struct Budget {
    pub(crate) limit: u64,
    plan_limit: i64,
    remaining_quota: i64,
}

impl Budget {
    pub(crate) fn new(plan: &Plan, used: i64, server_cap: usize) -> Self {
        let remaining_quota = plan.storage_quota_bytes.saturating_sub(used).max(0);
        let limit = plan
            .max_upload_bytes
            .max(0)
            .min(remaining_quota)
            .min(server_cap as i64) as u64;
        Self {
            limit,
            plan_limit: plan.max_upload_bytes,
            remaining_quota,
        }
    }

    pub(crate) fn exceeded(&self) -> AppError {
        if self.limit as i64 == self.plan_limit {
            AppError::PaymentRequired("file is too large, consider upgrading your plan.".to_owned())
        } else if self.limit as i64 == self.remaining_quota {
            AppError::PaymentRequired(
                "storage quota exceeded, consider upgrading your plan.".to_owned(),
            )
        } else {
            AppError::PayloadTooLarge("file exceeds the maximum upload size".to_owned())
        }
    }
}

/// the optional key only the share link carries, mixed into the content key
pub(crate) type UserKey = [u8; crypto::KEY_LEN];

pub(crate) struct Uploaded {
    pub(crate) s3_key: String,
    pub(crate) mime_type: String,
    pub(crate) size_bytes: i64,
    /// the content key salt
    pub(crate) encryption_iv: [u8; crypto::IV_LEN],
    pub(crate) dek: [u8; crypto::KEY_LEN],
    pub(crate) user_key: Option<UserKey>,
}

async fn store_field(
    state: &AppState,
    field: Field,
    budget: &Budget,
    encrypt_for_user: bool,
    lossless_images: bool,
) -> Result<Uploaded, AppError> {
    let mut prefix = Vec::with_capacity(SNIFF_BYTES);
    let mut field = Some(field);
    fill(&mut prefix, &mut field, SNIFF_BYTES).await?;
    if prefix.is_empty() {
        return Err(AppError::BadRequest("missing file".into()));
    }

    let mime_type = if content_type::needs_whole_body(&prefix) {
        let limit = state.config.max_image_decode_bytes;
        fill(&mut prefix, &mut field, limit + 1).await?;
        if prefix.len() > limit {
            content_type::FALLBACK_MIME_TYPE.to_string()
        } else {
            content_type::detect(&prefix)
        }
    } else {
        content_type::detect(&prefix)
    };

    if lossless_images && field.is_none() {
        prefix = recompress(prefix, &mime_type).await?;
    }

    let extension = content_type::extension_for(&mime_type);
    let s3_key = format!("{}.{extension}", Uuid::new_v4());

    let user_key = encrypt_for_user.then(crypto::random_key);
    let dek = crypto::random_key();
    let encryption_iv = crypto::random_iv();
    let mut sealer = crypto::Sealer::new(&crypto::content_key(
        &dek,
        &encryption_iv,
        user_key.as_ref(),
    ));

    let (tx, rx) = mpsc::channel::<Result<Bytes, AppError>>(CHANNEL_DEPTH);

    let storage = state.storage.clone();
    let writer_key = s3_key.clone();
    let writer_type = mime_type.clone();
    let sent_whole_body = Arc::new(AtomicBool::new(false));
    let writer_saw = sent_whole_body.clone();

    let writer = tokio::spawn(async move {
        let body = stream::unfold((rx, writer_saw, false), |(mut rx, saw, done)| async move {
            if done {
                return None;
            }
            match rx.recv().await {
                Some(chunk) => Some((chunk, (rx, saw, false))),
                None if saw.load(Ordering::SeqCst) => None,
                None => {
                    let e =
                        AppError::BadRequest("upload ended before the body was complete".into());
                    Some((Err(e), (rx, saw, true)))
                }
            }
        });
        storage
            .save_stream(&writer_key, &writer_type, Box::pin(body))
            .await
    });

    let mut written = 0u64;
    let mut prefix = Bytes::from(prefix);

    let whole_body = loop {
        let chunk = if !prefix.is_empty() {
            prefix.split_to(prefix.len().min(PUMP_CHUNK))
        } else {
            let Some(reading) = field.as_mut() else {
                break true;
            };
            match within_idle_timeout(reading.try_next()).await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break true,
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    break false;
                }
            }
        };

        written += chunk.len() as u64;
        if written > budget.limit {
            let _ = tx.send(Err(budget.exceeded())).await;
            break false;
        }

        let sealed = match sealer.push(&chunk) {
            Ok(sealed) => sealed,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                break false;
            }
        };
        if tx.send(Ok(Bytes::from(sealed))).await.is_err() {
            break false;
        }
    };

    // the final segment is only sealed once we know it is the final one
    if whole_body {
        sent_whole_body.store(true, Ordering::SeqCst);
        let last = sealer.finish().map(Bytes::from);
        let _ = tx.send(last).await;
    }
    drop(tx);
    writer
        .await
        .map_err(|e| AppError::internal_from("upload writer panicked", e))??;

    Ok(Uploaded {
        s3_key,
        mime_type,
        size_bytes: written as i64,
        encryption_iv,
        dek,
        user_key,
    })
}

async fn recompress(bytes: Vec<u8>, mime_type: &str) -> Result<Vec<u8>, AppError> {
    let mime_type = mime_type.to_owned();

    tokio::task::spawn_blocking(move || {
        image_compress::recompress(&bytes, &mime_type).unwrap_or(bytes)
    })
    .await
    .map_err(|e| AppError::internal_from("image recompression panicked", e))
}

async fn fill(buf: &mut Vec<u8>, field: &mut Option<Field>, target: usize) -> Result<(), AppError> {
    while buf.len() < target {
        let Some(reading) = field.as_mut() else {
            return Ok(());
        };
        match within_idle_timeout(reading.try_next()).await? {
            Some(chunk) => buf.extend_from_slice(&chunk),
            None => {
                *field = None;
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn read_text_field(mut field: Field) -> Result<String, AppError> {
    let mut buf = Vec::new();
    while let Some(chunk) = within_idle_timeout(field.try_next()).await? {
        if buf.len() + chunk.len() > MAX_TEXT_FIELD_BYTES {
            return Err(AppError::BadRequest("form field is too long".into()));
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).map_err(|_| AppError::BadRequest("form field is not valid utf-8".into()))
}

async fn drain_field(mut field: Field) -> Result<(), AppError> {
    while within_idle_timeout(field.try_next()).await?.is_some() {}
    Ok(())
}

/// awaits the next piece of the request body, failing when the client stalls
async fn within_idle_timeout<T>(
    next: impl std::future::Future<Output = Result<T, actix_multipart::MultipartError>>,
) -> Result<T, AppError> {
    match tokio::time::timeout(BODY_IDLE_TIMEOUT, next).await {
        Ok(result) => result.map_err(malformed_body),
        Err(_) => Err(AppError::BadRequest("upload stalled".into())),
    }
}

fn declared_length(req: &HttpRequest) -> Option<u64> {
    req.headers()
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

fn malformed_body(e: actix_multipart::MultipartError) -> AppError {
    AppError::BadRequest(format!("malformed multipart body: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test, App};
    use futures_util::StreamExt;
    use iono_core::state::CoreState;
    use iono_core::Config;

    const BODY: usize = 20 * 1024 * 1024;
    const BOUNDARY: &str = "----ionotestboundary";

    struct Fixture {
        state: web::Data<CoreState>,
        user_id: String,
        api_token: String,
    }

    impl Fixture {
        async fn new(plan: &str) -> Self {
            dotenvy::from_path("../../../.env").ok();
            let state =
                web::Data::new(CoreState::build(&Config::from_env().expect("test config")).await);

            let user_id = Uuid::new_v4().to_string();
            let api_token = token::generate_api_token();

            sqlx::query("INSERT INTO users (id, username, plan_id) VALUES ($1, $2, $3)")
                .bind(&user_id)
                .bind(format!("streamtest-{user_id}"))
                .bind(plan)
                .execute(&state.db)
                .await
                .expect("could not create the test user");

            sqlx::query("INSERT INTO api_keys (id, user_id, token_hash, token_prefix) VALUES ($1, $2, $3, $4)")
                .bind(Uuid::new_v4().to_string())
                .bind(&user_id)
                .bind(token::hash_api_token(&api_token))
                .bind(&api_token[..12])
                .execute(&state.db)
                .await
                .expect("could not create the test api key");

            Self {
                state,
                user_id,
                api_token,
            }
        }

        async fn set_encrypt_uploads(&self, on: bool) {
            sqlx::query("UPDATE user_settings SET encrypt_uploads = $1 WHERE user_id = $2")
                .bind(on)
                .bind(&self.user_id)
                .execute(&self.state.db)
                .await
                .unwrap();
        }

        async fn set_lossless_images(&self, on: bool) {
            sqlx::query("UPDATE user_settings SET lossless_images = $1 WHERE user_id = $2")
                .bind(on)
                .bind(&self.user_id)
                .execute(&self.state.db)
                .await
                .unwrap();
        }

        async fn upload(&self, body: Vec<u8>) -> (StatusCode, serde_json::Value) {
            let app =
                test::init_service(App::new().app_data(self.state.clone()).service(upload_file))
                    .await;

            let req = test::TestRequest::post()
                .uri("/")
                .insert_header(("authorization", format!("Bearer {}", self.api_token)))
                .insert_header((
                    "content-type",
                    format!("multipart/form-data; boundary={BOUNDARY}"),
                ))
                .set_payload(body)
                .to_request();

            let resp = test::call_service(&app, req).await;
            let status = resp.status();
            (status, test::read_body_json(resp).await)
        }

        async fn file_count(&self) -> i64 {
            sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM files WHERE user_id = $1")
                .bind(&self.user_id)
                .fetch_one(&self.state.db)
                .await
                .unwrap()
                .0
        }

        async fn fetch_and_decrypt(&self, user_key: Option<&str>) -> Vec<u8> {
            let row = sqlx::query_as::<_, File>(
                "SELECT * FROM files WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(&self.user_id)
            .fetch_one(&self.state.db)
            .await
            .expect("no file row was written");

            let object = self
                .state
                .storage
                .get(&row.original_name, None)
                .await
                .unwrap();
            let mut cipher = Vec::new();
            let mut body = object.stream;
            while let Some(chunk) = body.next().await {
                cipher.extend_from_slice(&chunk.unwrap());
            }

            let kek = self
                .state
                .keyring
                .get(row.encryption_key_version.unwrap())
                .unwrap();
            assert_eq!(row.encryption_format, crypto::FORMAT_SEGMENTED_GCM);
            let dek = crypto::open_key(
                kek,
                row.dek_iv.as_deref().unwrap(),
                row.wrapped_dek.as_deref().unwrap(),
                &crypto::file_key_aad(&row.id),
            )
            .unwrap();
            let user_key = user_key.map(|k| crypto::parse_key(k).unwrap());
            let key = crypto::content_key(
                &dek,
                row.encryption_iv.as_deref().unwrap(),
                user_key.as_ref(),
            );

            let size = row.size_bytes as u64;
            let range = crypto::sealed_range(size, 0, size - 1);
            let mut opener = crypto::Opener::new(&key, size, &range);
            let plain = opener.push(&cipher).unwrap();
            opener.finish().unwrap();
            plain
        }

        async fn cleanup(&self) {
            let keys = sqlx::query_as::<_, (String,)>(
                "SELECT original_name FROM files WHERE user_id = $1",
            )
            .bind(&self.user_id)
            .fetch_all(&self.state.db)
            .await
            .unwrap();
            for (key,) in keys {
                let _ = self.state.storage.delete(&key).await;
            }
            sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(&self.user_id)
                .execute(&self.state.db)
                .await
                .unwrap();
        }
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn real_png(side: u32) -> Vec<u8> {
        let mut seed = 0x9E37_79B9u32;
        let mut raw = Vec::with_capacity((side * side * 3) as usize);
        for _ in 0..side * side * 3 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            raw.push((seed >> 16) as u8);
        }

        let img = image::RgbImage::from_raw(side, side, raw).unwrap();
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .unwrap();
        bytes
    }

    fn loose_png(side: u32) -> Vec<u8> {
        let img = image::RgbImage::from_pixel(side, side, image::Rgb([17, 99, 240]));
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_with_encoder(image::codecs::png::PngEncoder::new_with_quality(
                &mut bytes,
                image::codecs::png::CompressionType::Fast,
                image::codecs::png::FilterType::NoFilter,
            ))
            .unwrap();
        bytes
    }

    fn pixels(bytes: &[u8]) -> image::RgbaImage {
        image::load_from_memory(bytes).unwrap().to_rgba8()
    }

    fn multipart_body(file: &[u8], password: Option<&str>) -> Vec<u8> {
        let mut body = Vec::with_capacity(file.len() + 512);
        if let Some(password) = password {
            body.extend_from_slice(format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{password}\r\n"
            ).as_bytes());
        }
        body.extend_from_slice(format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"blob.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        ).as_bytes());
        body.extend_from_slice(file);
        body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
        body
    }

    fn query_param(url: &str, name: &str) -> Option<String> {
        url.split_once('?')?
            .1
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
            .map(str::to_owned)
    }

    #[actix_web::test]
    #[ignore = "needs postgres and a live s3 endpoint"]
    async fn a_body_larger_than_one_part_round_trips_byte_for_byte() {
        let fixture = Fixture::new("pro").await;
        fixture.set_encrypt_uploads(false).await;

        let file = pattern(BODY);
        let (status, json) = fixture.upload(multipart_body(&file, None)).await;
        assert_eq!(status, StatusCode::CREATED, "response was {json}");

        let recovered = fixture.fetch_and_decrypt(None).await;
        assert_eq!(recovered.len(), file.len(), "size changed in transit");
        assert_eq!(recovered, file, "bytes changed in transit");

        let size = sqlx::query_as::<_, (i64,)>("SELECT size_bytes FROM files WHERE user_id = $1")
            .bind(&fixture.user_id)
            .fetch_one(&fixture.state.db)
            .await
            .unwrap();
        assert_eq!(size.0 as usize, BODY, "recorded size is wrong");

        fixture.cleanup().await;
    }

    #[actix_web::test]
    #[ignore = "needs postgres and a live s3 endpoint"]
    async fn a_user_encrypted_body_round_trips_byte_for_byte() {
        let fixture = Fixture::new("pro").await;
        fixture.set_encrypt_uploads(true).await;

        let file = pattern(BODY);
        let (status, json) = fixture.upload(multipart_body(&file, None)).await;
        assert_eq!(status, StatusCode::CREATED, "response was {json}");

        let url = json["url"].as_str().expect("no url in the response");
        let key = query_param(url, "key").expect("no user key in the url");

        assert_eq!(fixture.fetch_and_decrypt(Some(&key)).await, file);

        fixture.cleanup().await;
    }

    #[actix_web::test]
    #[ignore = "needs postgres and a live s3 endpoint"]
    async fn an_image_larger_than_the_sniff_window_is_still_detected() {
        let fixture = Fixture::new("pro").await;
        fixture.set_encrypt_uploads(false).await;

        let file = real_png(256);
        assert!(
            file.len() > SNIFF_BYTES,
            "the fixture must outgrow the sniff window to be meaningful"
        );

        let (status, json) = fixture.upload(multipart_body(&file, None)).await;
        assert_eq!(status, StatusCode::CREATED, "response was {json}");

        let content_type =
            sqlx::query_as::<_, (String,)>("SELECT content_type FROM files WHERE user_id = $1")
                .bind(&fixture.user_id)
                .fetch_one(&fixture.state.db)
                .await
                .unwrap();
        assert_eq!(content_type.0, "image/png", "the image was not recognised");

        let url = json["url"].as_str().unwrap();
        assert!(url.ends_with(".png"), "wrong extension in {url}");

        assert_eq!(
            fixture.fetch_and_decrypt(None).await,
            file,
            "the sniffed prefix did not reach the object intact"
        );

        fixture.cleanup().await;
    }

    #[actix_web::test]
    #[ignore = "needs postgres and a live s3 endpoint"]
    async fn a_spoofed_image_signature_falls_back_and_still_stores() {
        let fixture = Fixture::new("pro").await;
        fixture.set_encrypt_uploads(false).await;

        let mut file = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        file.extend_from_slice(&pattern(BODY));

        let (status, json) = fixture.upload(multipart_body(&file, None)).await;
        assert_eq!(status, StatusCode::CREATED, "response was {json}");

        let content_type =
            sqlx::query_as::<_, (String,)>("SELECT content_type FROM files WHERE user_id = $1")
                .bind(&fixture.user_id)
                .fetch_one(&fixture.state.db)
                .await
                .unwrap();
        assert_eq!(
            content_type.0, "application/octet-stream",
            "a spoofed signature was trusted"
        );
        assert_eq!(fixture.fetch_and_decrypt(None).await, file);

        fixture.cleanup().await;
    }

    #[actix_web::test]
    #[ignore = "needs postgres and a live s3 endpoint"]
    async fn a_password_field_before_the_file_still_uploads() {
        let fixture = Fixture::new("pro").await;
        fixture.set_encrypt_uploads(false).await;

        let file = pattern(9 * 1024 * 1024);
        let (status, json) = fixture
            .upload(multipart_body(&file, Some("hunter22!")))
            .await;
        assert_eq!(status, StatusCode::CREATED, "response was {json}");

        let hash = sqlx::query_as::<_, (Option<String>,)>(
            "SELECT password_hash FROM files WHERE user_id = $1",
        )
        .bind(&fixture.user_id)
        .fetch_one(&fixture.state.db)
        .await
        .unwrap();
        assert!(hash.0.is_some(), "the password was not recorded");
        assert_eq!(fixture.fetch_and_decrypt(None).await, file);

        fixture.cleanup().await;
    }

    #[actix_web::test]
    #[ignore = "needs postgres and a live s3 endpoint"]
    async fn lossless_shrinks_the_object_without_touching_a_pixel() {
        let fixture = Fixture::new("pro").await;
        fixture.set_encrypt_uploads(false).await;
        fixture.set_lossless_images(true).await;

        let file = loose_png(256);
        let (status, json) = fixture.upload(multipart_body(&file, None)).await;
        assert_eq!(status, StatusCode::CREATED, "response was {json}");

        let stored = fixture.fetch_and_decrypt(None).await;
        assert!(
            stored.len() < file.len(),
            "{} bytes stored for a {} byte upload, it was not recompressed",
            stored.len(),
            file.len()
        );
        assert_eq!(
            pixels(&stored),
            pixels(&file),
            "a lossless re-encode changed the image"
        );

        let size = sqlx::query_as::<_, (i64,)>("SELECT size_bytes FROM files WHERE user_id = $1")
            .bind(&fixture.user_id)
            .fetch_one(&fixture.state.db)
            .await
            .unwrap();
        assert_eq!(
            size.0 as usize,
            stored.len(),
            "the recorded size does not match the object, so quota is wrong"
        );

        fixture.cleanup().await;
    }

    #[actix_web::test]
    #[ignore = "needs postgres and a live s3 endpoint"]
    async fn the_same_image_is_untouched_with_lossless_off() {
        let fixture = Fixture::new("pro").await;
        fixture.set_encrypt_uploads(false).await;
        fixture.set_lossless_images(false).await;

        let file = loose_png(256);
        let (status, json) = fixture.upload(multipart_body(&file, None)).await;
        assert_eq!(status, StatusCode::CREATED, "response was {json}");

        assert_eq!(
            fixture.fetch_and_decrypt(None).await,
            file,
            "the upload was re-encoded despite lossless_images being off"
        );

        fixture.cleanup().await;
    }

    #[actix_web::test]
    #[ignore = "needs postgres and a live s3 endpoint"]
    async fn lossless_leaves_a_non_image_alone() {
        let fixture = Fixture::new("pro").await;
        fixture.set_encrypt_uploads(false).await;
        fixture.set_lossless_images(true).await;

        let file = pattern(BODY);
        let (status, json) = fixture.upload(multipart_body(&file, None)).await;
        assert_eq!(status, StatusCode::CREATED, "response was {json}");

        assert_eq!(
            fixture.fetch_and_decrypt(None).await,
            file,
            "a non-image body was altered"
        );

        fixture.cleanup().await;
    }

    #[actix_web::test]
    #[ignore = "needs postgres and a live s3 endpoint"]
    async fn an_oversized_body_is_rejected_and_stores_nothing() {
        let fixture = Fixture::new("free").await;

        let file = pattern(90 * 1024 * 1024);
        let (status, _) = fixture.upload(multipart_body(&file, None)).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(
            fixture.file_count().await,
            0,
            "a rejected upload wrote a row"
        );

        fixture.cleanup().await;
    }
}
