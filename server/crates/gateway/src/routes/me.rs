use actix_web::{get, HttpResponse};

use crate::{auth::JwtUser, error::ApiResult};

#[get("/me")]
pub async fn me(user: JwtUser) -> ApiResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(user.0)) // TODO: add more data here
}
