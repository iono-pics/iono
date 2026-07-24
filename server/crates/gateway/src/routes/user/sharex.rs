use actix_web::{get, http::header, web, HttpResponse};
use iono_core::web::ApiResult;
use serde::Deserialize;
use serde_json::json;
use utoipa::ToSchema;

use crate::{auth::ApiKeyAuth, state::AppState};

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DestinationKind {
    File,
    Paste,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SharexQuery {
    r#type: DestinationKind,
}

#[utoipa::path(
    get,
    path = "/user/sharex",
    security(("bearer_auth" = [])),
    params(("type" = DestinationKind, Query, description = "which destination to generate")),
    responses(
        (status = 200, description = "sharex custom uploader config"),
        (status = 400, description = "unknown destination type"),
        (status = 401, description = "missing or invalid api key")
    )
)]
#[get("/sharex")]
pub async fn sharex_config(
    state: web::Data<AppState>,
    auth: ApiKeyAuth,
    query: web::Query<SharexQuery>,
) -> ApiResult<HttpResponse> {
    let ApiKeyAuth(api_key) = auth;
    let (filename, config) = build_config(
        &query.into_inner().r#type,
        &api_key,
        &state.config.public_ingest_url,
    );

    Ok(HttpResponse::Ok()
        .insert_header((
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        ))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(config))
}

fn build_config(
    kind: &DestinationKind,
    api_key: &str,
    ingest_url: &str,
) -> (&'static str, serde_json::Value) {
    let authorization = format!("Bearer {api_key}");

    match kind {
        DestinationKind::File => (
            "iono-file.sxcu",
            json!({
                "Version": "21.0.0",
                "Name": "iono (images)",
                "DestinationType": "ImageUploader, FileUploader",
                "RequestMethod": "POST",
                "RequestURL": format!("{ingest_url}/"),
                "Headers": { "Authorization": authorization },
                "Body": "MultipartFormData",
                "FileFormName": "file",
                "URL": "{json:url}",
            }),
        ),
        DestinationKind::Paste => (
            "iono-paste.sxcu",
            json!({
                "Version": "21.0.0",
                "Name": "iono (pastes)",
                "DestinationType": "TextUploader",
                "RequestMethod": "POST",
                "RequestURL": format!("{ingest_url}/pastes"),
                "Headers": { "Authorization": authorization },
                "Body": "JSON",
                "Data": "{\"content\":\"{input}\"}",
                "URL": "{json:url}",
            }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_config_targets_the_ingest_upload_route() {
        let (filename, config) = build_config(
            &DestinationKind::File,
            "iono_secret",
            "https://up.iono.pics",
        );

        assert_eq!(filename, "iono-file.sxcu");
        assert_eq!(config["RequestURL"], "https://up.iono.pics/");
        assert_eq!(config["FileFormName"], "file");
        assert_eq!(config["Headers"]["Authorization"], "Bearer iono_secret");
    }

    #[test]
    fn paste_config_posts_json_to_the_gateway() {
        let (filename, config) = build_config(
            &DestinationKind::Paste,
            "iono_secret",
            "https://up.iono.pics",
        );

        assert_eq!(filename, "iono-paste.sxcu");
        assert_eq!(config["RequestURL"], "https://up.iono.pics/pastes");
        assert_eq!(config["Body"], "JSON");

        let data: serde_json::Value =
            serde_json::from_str(config["Data"].as_str().unwrap()).unwrap();
        assert_eq!(data["content"], "{input}");
    }

    #[test]
    fn destination_kind_parses_from_lowercase() {
        let kind: DestinationKind = serde_json::from_str("\"paste\"").unwrap();
        assert!(matches!(kind, DestinationKind::Paste));
        assert!(serde_json::from_str::<DestinationKind>("\"nope\"").is_err());
    }
}
