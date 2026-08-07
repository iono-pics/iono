use actix_web::{http::header, post, web, HttpRequest, HttpResponse};
use iono_core::{
    auth::{jwt, refresh::SessionContext},
    web::ApiResult,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{
    routes::auth::{
        discord::{
            consume_flow_and_fetch, link_to_user, login_or_signup, DiscordAuthResponse,
            LoginOutcome,
        },
        signed_in_payload,
    },
    state::AppState,
};

#[derive(Debug, Deserialize, ToSchema)]
pub struct DiscordLoginRequest {
    code: String,
    state: String,
}

#[utoipa::path(
    post,
    path = "/auth/discord/login",
    request_body = DiscordLoginRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "signed in, or {mfa_required: true, mfa_token, methods} if the account has mfa", body = DiscordAuthResponse),
        (status = 201, description = "account created and signed in", body = DiscordAuthResponse),
        (status = 204, description = "discord linked to your account"),
        (status = 400, description = "invalid request"),
        (status = 401, description = "authorization failed"),
        (status = 409, description = "that discord account is linked elsewhere"),
    )
)]
#[post("/discord/login")]
pub async fn discord_login(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<DiscordLoginRequest>,
) -> ApiResult<HttpResponse> {
    let body = body.into_inner();

    let (tokens, discord_user, link_user_id_from_flow) =
        consume_flow_and_fetch(&state, &body.state, &body.code).await?;

    let bearer_user_id = if let Some(bearer) = extract_bearer(&req) {
        let user =
            jwt::authenticate(&state.db, state.config.jwt_secret.expose_secret(), &bearer).await?;
        Some(user.id)
    } else {
        None
    };

    let link_target = bearer_user_id.or(link_user_id_from_flow);

    if let Some(user_id) = link_target {
        link_to_user(&state, &user_id, &tokens, &discord_user).await?;
        return Ok(HttpResponse::NoContent().finish());
    }

    let outcome = login_or_signup(
        &state.db,
        state.config.jwt_secret.expose_secret(),
        &tokens,
        &discord_user,
    )
    .await?;

    match outcome {
        LoginOutcome::MfaRequired(challenge) => Ok(HttpResponse::Ok().json(challenge.json())),
        LoginOutcome::SignedIn {
            user_id,
            token_version,
            is_new_user,
        } => {
            let mut payload = signed_in_payload(
                &state,
                &user_id,
                token_version,
                &SessionContext::from_request(&req),
            )
            .await?;
            payload["is_new_user"] = is_new_user.into();

            if is_new_user {
                Ok(HttpResponse::Created().json(payload))
            } else {
                Ok(HttpResponse::Ok().json(payload))
            }
        }
    }
}

fn extract_bearer(req: &HttpRequest) -> Option<String> {
    let value = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}
