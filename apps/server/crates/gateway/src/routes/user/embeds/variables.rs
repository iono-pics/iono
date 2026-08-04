use actix_web::{get, HttpResponse};
use iono_core::{embed_vars::EMBED_VARIABLES, web::ApiResult};
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::AuthedUser;

#[derive(Debug, Serialize, ToSchema)]
pub struct EmbedVariableSummary {
    placeholder: String,
    name: String,
    description: String,
}

#[utoipa::path(
    get,
    path = "/user/embeds/variables",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "variables usable in preset text", body = [EmbedVariableSummary]),
        (status = 401, description = "missing or invalid token"),
    )
)]
#[get("/embeds/variables")]
pub async fn list_embed_variables(_user: AuthedUser) -> ApiResult<HttpResponse> {
    let variables = EMBED_VARIABLES
        .iter()
        .map(|v| EmbedVariableSummary {
            placeholder: format!("{{{}}}", v.name),
            name: v.name.to_string(),
            description: v.description.to_string(),
        })
        .collect::<Vec<_>>();

    Ok(HttpResponse::Ok().json(variables))
}
