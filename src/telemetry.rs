use opentelemetry::{global, runtime::TokioCurrentThread};
use opentelemetry_zipkin::Propagator;
use anyhow::Result;

pub async fn init_tracer() -> Result<opentelemetry::sdk::trace::Tracer> {

    use reqwest::header;
    let cb = reqwest::Client::builder();
    let mut headers = header::HeaderMap::new();
    let mut sf_token = header::HeaderValue::from_str(&std::env::var("OTEL_EXPORTER_JAEGER_PASSWORD")?)?;
    sf_token.set_sensitive(true);
    headers.insert("X-SF-Token", sf_token);
    
    let client = cb.default_headers(headers).build()?;

    global::set_text_map_propagator(Propagator::new());

    let tracer = opentelemetry_zipkin::new_pipeline()
        // providing a custom client here so we can inject the required HTTP headers
        // to work with signalfx
        .with_collector_endpoint(&std::env::var("OTEL_EXPORTER_ZIPKIN_ENDPOINT")?)
        .with_http_client(client)
        .install_batch(TokioCurrentThread)?;
    Ok(tracer)
}
