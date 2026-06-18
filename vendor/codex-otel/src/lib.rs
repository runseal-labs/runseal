use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsigMetricsSettings {
    pub environment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtelExporter {
    None,
    Statsig,
}

#[derive(Debug, Clone)]
pub struct OtelSettings {
    pub environment: String,
    pub service_name: String,
    pub service_version: String,
    pub codex_home: PathBuf,
    pub exporter: OtelExporter,
    pub trace_exporter: OtelExporter,
    pub metrics_exporter: OtelExporter,
    pub runtime_metrics: bool,
    pub span_attributes: BTreeMap<String, String>,
    pub tracestate: BTreeMap<String, String>,
}

pub struct OtelProvider;

pub struct Metrics;

impl OtelProvider {
    pub fn from(_settings: &OtelSettings) -> anyhow::Result<Option<Self>> {
        Ok(None)
    }

    pub fn metrics(&self) -> Option<Metrics> {
        None
    }

    pub fn shutdown(self) {}
}

impl Metrics {
    pub fn counter(&self, _name: &str, _inc: u64, _tags: &[(&str, &str)]) -> anyhow::Result<()> {
        Ok(())
    }
}

pub fn global_statsig_metrics_settings() -> Option<StatsigMetricsSettings> {
    None
}
