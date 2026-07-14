use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    web, App, Error, HttpServer,
};
use tracing::Span;
use tracing_actix_web::{DefaultRootSpanBuilder, RootSpanBuilder, TracingLogger};

use iono_core::{db, storage, Config};

mod embed;
mod error;
mod routes;
mod state;

use state::AppState;

// file passwords are in query string so spans must only record the path
struct PathOnlyRootSpan;

impl RootSpanBuilder for PathOnlyRootSpan {
    fn on_request_start(request: &ServiceRequest) -> Span {
        tracing::info_span!(
            "HTTP request",
            http.method = %request.method(),
            http.target = %request.uri().path(),
            http.status_code = tracing::field::Empty,
            otel.status_code = tracing::field::Empty,
            exception.message = tracing::field::Empty,
            exception.details = tracing::field::Empty,
        )
    }

    fn on_request_end<B: MessageBody>(span: Span, outcome: &Result<ServiceResponse<B>, Error>) {
        DefaultRootSpanBuilder::on_request_end(span, outcome);
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env();

    let storage = storage::build(&config)
        .await
        .expect("failed to initialize storage backend");

    let db = db::build(&config)
        .await
        .expect("failed to connect to database");

    let host = config.host.clone();
    let port = config.viewer_port;

    tracing::info!("iono-viewer listening on http://{}:{}", host, port);

    let state = web::Data::new(AppState {
        storage,
        db,
        config,
    });

    HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::<PathOnlyRootSpan>::new())
            .app_data(state.clone())
            .configure(routes::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
