pub mod sweep;

use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(sweep::sweep);
}
