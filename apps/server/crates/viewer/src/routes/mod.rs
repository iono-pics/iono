pub mod link;
pub mod paste;
pub mod view;

use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(link::follow_short_link_with_prefix)
        .service(link::follow_short_link)
        .service(paste::view_paste_with_prefix)
        .service(paste::view_paste)
        .service(view::raw::raw_file)
        .service(view::raw_with_prefix::raw_file_with_prefix)
        .service(view::view_with_prefix::view_page_with_prefix)
        .service(view::page::view_page);
}
