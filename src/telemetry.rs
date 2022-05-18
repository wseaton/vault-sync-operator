use opentelemetry::Key;
use opentelemetry::{global, runtime::TokioCurrentThread};
use anyhow::Result;

use opentelemetry::{KeyValue, trace::Tracer};
use opentelemetry::sdk::{trace::{self, IdGenerator, Sampler}, Resource};
use opentelemetry::util::tokio_interval_stream;
use opentelemetry_otlp::{Protocol, WithExportConfig, ExportConfig};
use std::time::Duration;



pub async fn init_tracer() -> Result<opentelemetry::sdk::trace::Tracer> {

    use reqwest::header;
    let cb = reqwest::Client::builder();
    let mut headers = header::HeaderMap::new();
    let mut sf_token = header::HeaderValue::from_str(&std::env::var("OTEL_EXPORTER_JAEGER_PASSWORD")?)?;
    sf_token.set_sensitive(true);
    headers.insert("X-SF-Token", sf_token);    
    let client = cb.default_headers(headers).build()?;

    let tracer = opentelemetry_otlp::new_pipeline()
        // providing a custom client here so we can inject the required HTTP headers
        // to work with signalfx
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter().http()
            .with_timeout(Duration::from_secs(3))
            .with_endpoint(std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")?)
            .with_http_client(client)
         )
        .install_batch(opentelemetry::runtime::TokioCurrentThread)?;

    Ok(tracer)
}
