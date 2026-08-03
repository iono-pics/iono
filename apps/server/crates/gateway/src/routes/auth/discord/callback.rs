use actix_web::{get, http::header, web, HttpResponse};
use iono_core::{web::ApiResult, AppError};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Deserialize;
use serde_json::json;

use crate::{
    routes::auth::discord::{consume_flow_and_fetch, link_to_user, login_or_signup},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

enum Outcome {
    SignedIn(String),
    Linked,
    Error(String),
}

#[utoipa::path(
    get,
    path = "/auth/discord/callback",
    responses(
        (status = 200, description = "signed in, returns { access_token }"),
        (status = 204, description = "discord linked to your account"),
        (status = 302, description = "redirect back to the app, result is passed as a url fragment"),
        (status = 400, description = "invalid callback"),
        (status = 401, description = "authorization failed"),
    )
)]
#[get("/discord/callback")]
pub async fn discord_callback(
    state: web::Data<AppState>,
    query: web::Query<CallbackQuery>,
) -> ApiResult<HttpResponse> {
    let query = query.into_inner();

    if let Some(err) = query.error {
        return respond(&state, Outcome::Error(err));
    }

    let code = query
        .code
        .ok_or_else(|| AppError::BadRequest("missing code".into()))?;
    let csrf = query
        .state
        .ok_or_else(|| AppError::BadRequest("missing state".into()))?;

    let (tokens, discord_user, link_user_id) = consume_flow_and_fetch(&state, &csrf, &code).await?;

    if let Some(user_id) = link_user_id {
        link_to_user(&state, &user_id, &tokens, &discord_user).await?;
        return respond(&state, Outcome::Linked);
    }

    let (access_token, _is_new_user) = login_or_signup(&state, &tokens, &discord_user).await?;
    respond(&state, Outcome::SignedIn(access_token))
}

fn respond(state: &AppState, outcome: Outcome) -> ApiResult<HttpResponse> {
    if let Some(base) = state.config.discord_success_redirect_url.as_deref() {
        let base = base.split('#').next().unwrap_or(base);
        let fragment = match &outcome {
            Outcome::SignedIn(token) => {
                format!("token={}", utf8_percent_encode(token, NON_ALPHANUMERIC))
            }
            Outcome::Linked => "linked=1".to_string(),
            Outcome::Error(err) => {
                format!("error={}", utf8_percent_encode(err, NON_ALPHANUMERIC))
            }
        };
        let url = format!("{base}#{fragment}");
        return Ok(HttpResponse::Found()
            .append_header((header::LOCATION, url))
            .finish());
    }

    match outcome {
        Outcome::SignedIn(access_token) => {
            Ok(HttpResponse::Ok().json(json!({ "access_token": access_token })))
        }
        Outcome::Linked => Ok(HttpResponse::NoContent().finish()),
        Outcome::Error(err) => Err(AppError::BadRequest(err).into()),
    }
}
