use actix_web::{get, HttpResponse};

use iono_core::web::ApiResult;

use crate::auth::JwtUser;

#[utoipa::path(
    get,
    path = "/user/@me",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "the user"),
        (status = 401, description = "missing or invalid token")
    )
)]
#[get("/@me")]
pub async fn me(user: JwtUser) -> ApiResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(user.0)) // TODO: add more data here
}
