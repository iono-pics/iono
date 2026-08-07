use actix_web::{get, http::header, web, HttpRequest, HttpResponse};
use iono_core::{auth::refresh::SessionContext, web::ApiResult, AppError};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    routes::auth::{
        discord::{consume_flow_and_fetch, link_to_user, login_or_signup, LoginOutcome},
        signed_in_payload, MfaChallenge,
    },
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

enum Outcome {
    SignedIn(Value),
    MfaRequired(MfaChallenge),
    Linked,
    Error(String),
}

#[utoipa::path(
    get,
    path = "/auth/discord/callback",
    responses(
        (status = 200, description = "signed in, returns { access_token, refresh_token, expires_in }, or { mfa_required, mfa_token, methods } if the account has mfa"),
        (status = 204, description = "discord linked to your account"),
        (status = 302, description = "redirect back to the app, result is passed as a url fragment"),
        (status = 400, description = "invalid callback"),
        (status = 401, description = "authorization failed"),
        (status = 409, description = "the account requires a passkey but has none registered"),
    )
)]
#[get("/discord/callback")]
pub async fn discord_callback(
    req: HttpRequest,
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

    let login = login_or_signup(
        &state.db,
        state.config.jwt_secret.expose_secret(),
        &tokens,
        &discord_user,
    )
    .await?;

    let outcome = match login {
        LoginOutcome::SignedIn {
            user_id,
            token_version,
            ..
        } => Outcome::SignedIn(
            signed_in_payload(
                &state,
                &user_id,
                token_version,
                &SessionContext::from_request(&req),
            )
            .await?,
        ),
        LoginOutcome::MfaRequired(challenge) => Outcome::MfaRequired(challenge),
    };
    respond(&state, outcome)
}

fn respond(state: &AppState, outcome: Outcome) -> ApiResult<HttpResponse> {
    if let Some(base) = state.config.discord_success_redirect_url.as_deref() {
        let base = base.split('#').next().unwrap_or(base);
        let fragment = match &outcome {
            Outcome::SignedIn(payload) => {
                let field = |key: &str| payload[key].as_str().unwrap_or_default().to_string();
                format!(
                    "token={}&refresh_token={}&expires_in={}",
                    utf8_percent_encode(&field("access_token"), NON_ALPHANUMERIC),
                    utf8_percent_encode(&field("refresh_token"), NON_ALPHANUMERIC),
                    payload["expires_in"].as_i64().unwrap_or_default(),
                )
            }
            Outcome::MfaRequired(challenge) => format!(
                "mfa_required=1&mfa_token={}&methods={}",
                utf8_percent_encode(challenge.token(), NON_ALPHANUMERIC),
                challenge.methods().join(",")
            ),
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
        Outcome::SignedIn(payload) => Ok(HttpResponse::Ok().json(payload)),
        Outcome::MfaRequired(challenge) => Ok(HttpResponse::Ok().json(challenge.json())),
        Outcome::Linked => Ok(HttpResponse::NoContent().finish()),
        Outcome::Error(err) => Err(AppError::BadRequest(err).into()),
    }
}
