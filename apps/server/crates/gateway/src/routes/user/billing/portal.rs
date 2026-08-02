use actix_web::{post, web, HttpResponse};
use iono_core::{web::ApiResult, AppError};
use serde_json::json;
use std::collections::HashMap;

use crate::{auth::JwtUser, state::AppState};

#[utoipa::path(
    post,
    path = "/user/billing/portal",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "returns { url } to redirect the user to"),
        (status = 401, description = "missing or invalid token"),
        (status = 500, description = "stripe not configured, or stripe api call failed"),
    )
)]
#[post("/billing/portal")]
pub async fn create_portal_session(
    state: web::Data<AppState>,
    user: JwtUser,
) -> ApiResult<HttpResponse> {
    let Some(client) = state.stripe.as_ref() else {
        return Err(AppError::internal("stripe is not configured").into());
    };
    let Some(return_url) = state.config.stripe_portal_return_url.as_deref() else {
        return Err(AppError::internal("stripe portal return url is not configured").into());
    };

    let customer_id = match user.0.stripe_customer_id.clone() {
        Some(id) => id,
        None => {
            let mut params = stripe::CreateCustomer::new();
            params.email = user.0.email.as_deref();
            params.metadata = Some(HashMap::from([(
                "iono_user_id".to_string(),
                user.0.id.clone(),
            )]));
            let customer = stripe::Customer::create(client, params)
                .await
                .map_err(map_stripe)?;
            let id = customer.id.to_string();
            sqlx::query("UPDATE users SET stripe_customer_id = $1 WHERE id = $2")
                .bind(&id)
                .bind(&user.0.id)
                .execute(&state.db)
                .await
                .map_err(AppError::from)?;
            id
        }
    };

    let customer_id: stripe::CustomerId = customer_id
        .parse()
        .map_err(|e| AppError::internal(format!("bad stripe customer id: {e}")))?;
    let mut params = stripe::CreateBillingPortalSession::new(customer_id);
    params.return_url = Some(return_url);
    let session = stripe::BillingPortalSession::create(client, params)
        .await
        .map_err(map_stripe)?;

    Ok(HttpResponse::Ok().json(json!({ "url": session.url })))
}

fn map_stripe(err: stripe::StripeError) -> AppError {
    tracing::error!(error = %err, "stripe api call failed");
    AppError::internal("stripe api call failed")
}
