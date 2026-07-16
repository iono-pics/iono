pub mod view;

use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(view::raw::raw_file)
        .service(view::raw_with_prefix::raw_file_with_prefix)
        .service(view::view_with_prefix::view_page_with_prefix)
        .service(view::view::view_page);
}
