pub mod encrypt_backfill;
pub mod sweep;

use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(sweep::sweep)
        .service(encrypt_backfill::encrypt_backfill);
}
