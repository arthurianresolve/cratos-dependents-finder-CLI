//! Low-cardinality operational metrics and structured tracing initialization.

use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result};
use opentelemetry::{global, trace::TracerProvider as _};
use opentelemetry_sdk::trace::SdkTracerProvider;
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, gauge::Gauge},
    registry::Registry,
};
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _};

#[derive(Clone, Debug)]
pub struct CoordinatorMetrics {
    registry: Arc<Mutex<Registry>>,
    pub api_requests: Counter,
    pub authentication_failures: Counter,
    pub jobs_submitted: Counter,
    pub tasks_leased: Counter,
    pub tasks_completed: Counter,
    pub tasks_failed: Counter,
    pub active_agents: Gauge,
    pub retention_runs: Counter,
    pub retention_failures: Counter,
    pub retention_metadata_removed: Counter,
    pub retention_blobs_removed: Counter,
    pub retention_last_run_timestamp_seconds: Gauge,
    pub retention_last_run_succeeded: Gauge,
    pub retention_pending_candidates: Gauge,
}

impl CoordinatorMetrics {
    pub fn new() -> Self {
        let api_requests = Counter::default();
        let authentication_failures = Counter::default();
        let jobs_submitted = Counter::default();
        let tasks_leased = Counter::default();
        let tasks_completed = Counter::default();
        let tasks_failed = Counter::default();
        let active_agents = Gauge::default();
        let retention_runs = Counter::default();
        let retention_failures = Counter::default();
        let retention_metadata_removed = Counter::default();
        let retention_blobs_removed = Counter::default();
        let retention_last_run_timestamp_seconds = Gauge::default();
        let retention_last_run_succeeded = Gauge::default();
        let retention_pending_candidates = Gauge::default();
        let mut registry = Registry::default();
        registry.register(
            "coordinator_api_requests_total",
            "Authenticated coordinator API requests",
            api_requests.clone(),
        );
        registry.register(
            "coordinator_authentication_failures_total",
            "Rejected coordinator API identities",
            authentication_failures.clone(),
        );
        registry.register(
            "coordinator_jobs_submitted_total",
            "Durable scan jobs submitted",
            jobs_submitted.clone(),
        );
        registry.register(
            "coordinator_tasks_leased_total",
            "Repository task leases granted",
            tasks_leased.clone(),
        );
        registry.register(
            "coordinator_tasks_completed_total",
            "Repository tasks completed",
            tasks_completed.clone(),
        );
        registry.register(
            "coordinator_tasks_failed_total",
            "Repository task attempts failed",
            tasks_failed.clone(),
        );
        registry.register(
            "coordinator_active_agents",
            "Currently enrolled non-revoked agent identities",
            active_agents.clone(),
        );
        registry.register(
            "coordinator_retention_runs",
            "Bounded artifact retention sweeps",
            retention_runs.clone(),
        );
        registry.register(
            "coordinator_retention_failures",
            "Artifact retention sweeps that failed",
            retention_failures.clone(),
        );
        registry.register(
            "coordinator_retention_metadata_removed",
            "Expired artifact metadata records removed",
            retention_metadata_removed.clone(),
        );
        registry.register(
            "coordinator_retention_blobs_removed",
            "Expired encrypted artifact blobs removed",
            retention_blobs_removed.clone(),
        );
        registry.register(
            "coordinator_retention_last_run_timestamp_seconds",
            "Unix timestamp of the last artifact retention attempt",
            retention_last_run_timestamp_seconds.clone(),
        );
        registry.register(
            "coordinator_retention_last_run_succeeded",
            "Whether the last artifact retention attempt succeeded",
            retention_last_run_succeeded.clone(),
        );
        registry.register(
            "coordinator_retention_pending_candidates",
            "Expired artifact records remaining after the last successful sweep",
            retention_pending_candidates.clone(),
        );
        Self {
            registry: Arc::new(Mutex::new(registry)),
            api_requests,
            authentication_failures,
            jobs_submitted,
            tasks_leased,
            tasks_completed,
            tasks_failed,
            active_agents,
            retention_runs,
            retention_failures,
            retention_metadata_removed,
            retention_blobs_removed,
            retention_last_run_timestamp_seconds,
            retention_last_run_succeeded,
            retention_pending_candidates,
        }
    }

    pub fn render(&self) -> Result<String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| anyhow::anyhow!("metrics registry lock poisoned"))?;
        let mut output = String::new();
        encode(&mut output, &registry).context("encoding Prometheus metrics")?;
        Ok(output)
    }
}

impl Default for CoordinatorMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Keeps the optional batch exporter alive and flushes it on orderly shutdown.
#[derive(Debug)]
pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take()
            && let Err(error) = provider.shutdown()
        {
            eprintln!("failed to flush OpenTelemetry spans: {error}");
        }
    }
}

/// Install structured tracing and, when `OTEL_EXPORTER_OTLP_ENDPOINT` is set,
/// an OTLP/HTTP batch exporter. Calling this more than once remains an error so
/// binaries cannot silently discard telemetry.
pub fn initialize(json: bool) -> Result<TelemetryGuard> {
    crate::install_rustls_crypto_provider();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let otlp_enabled = std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_some();
    let provider = if otlp_enabled {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .build()
            .context("building OTLP/HTTP span exporter")?;
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .build();
        global::set_tracer_provider(provider.clone());
        let tracer = provider.tracer(env!("CARGO_PKG_NAME"));
        if json {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_current_span(false)
                        .with_span_list(false),
                )
                .try_init()
                .map_err(|error| anyhow::anyhow!("initializing JSON OTLP tracing: {error}"))?;
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .with(tracing_subscriber::fmt::layer())
                .try_init()
                .map_err(|error| anyhow::anyhow!("initializing OTLP tracing: {error}"))?;
        }
        Some(provider)
    } else {
        if json {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_current_span(false)
                        .with_span_list(false),
                )
                .try_init()
                .map_err(|error| anyhow::anyhow!("initializing JSON tracing: {error}"))?;
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer())
                .try_init()
                .map_err(|error| anyhow::anyhow!("initializing tracing: {error}"))?;
        }
        None
    };
    Ok(TelemetryGuard { provider })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_retention_outcome_metrics() {
        let metrics = CoordinatorMetrics::new();
        metrics.retention_runs.inc();
        metrics.retention_last_run_succeeded.set(1);
        metrics.retention_pending_candidates.set(7);

        let rendered = metrics.render().unwrap();
        assert!(rendered.contains("coordinator_retention_runs_total 1"));
        assert!(rendered.contains("coordinator_retention_last_run_succeeded 1"));
        assert!(rendered.contains("coordinator_retention_pending_candidates 7"));
    }
}
