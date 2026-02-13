//! Metrics collector for authorization operations.

use std::collections::HashMap;
use std::sync::Mutex;

pub trait MetricsCollector: Send + Sync {
    fn increment(&self, metric: &str, labels: Option<&HashMap<String, String>>);
    fn observe(&self, metric: &str, value: f64, labels: Option<&HashMap<String, String>>);
}

pub struct DefaultMetricsCollector {
    counters: Mutex<HashMap<String, u64>>,
    histograms: Mutex<HashMap<String, Vec<f64>>>,
}

impl DefaultMetricsCollector {
    pub fn new() -> Self {
        Self {
            counters: Mutex::new(HashMap::new()),
            histograms: Mutex::new(HashMap::new()),
        }
    }

    fn make_key(metric: &str, labels: Option<&HashMap<String, String>>) -> String {
        match labels {
            Some(l) if !l.is_empty() => {
                let mut parts: Vec<String> = l.iter().map(|(k, v)| format!("{k}={v}")).collect();
                parts.sort();
                format!("{metric}{{{}}}", parts.join(","))
            }
            _ => metric.to_string(),
        }
    }

    pub fn get_counter(&self, metric: &str, labels: Option<&HashMap<String, String>>) -> u64 {
        let key = Self::make_key(metric, labels);
        *self.counters.lock().unwrap().get(&key).unwrap_or(&0)
    }
}

impl MetricsCollector for DefaultMetricsCollector {
    fn increment(&self, metric: &str, labels: Option<&HashMap<String, String>>) {
        let key = Self::make_key(metric, labels);
        *self.counters.lock().unwrap().entry(key).or_insert(0) += 1;
    }

    fn observe(&self, metric: &str, value: f64, labels: Option<&HashMap<String, String>>) {
        let key = Self::make_key(metric, labels);
        self.histograms.lock().unwrap().entry(key).or_default().push(value);
    }
}

impl Default for DefaultMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
