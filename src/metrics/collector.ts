/**
 * Metrics collector — tracks authorization performance and usage metrics.
 *
 * Provides a default in-memory implementation. Services can inject
 * their own MetricsCollector (e.g., Prometheus client) for production use.
 */

import { MetricsCollector } from '../types';

interface MetricEntry {
  value: number;
  labels: Record<string, string>;
}

export class DefaultMetricsCollector implements MetricsCollector {
  private counters: Map<string, MetricEntry[]> = new Map();
  private histograms: Map<string, MetricEntry[]> = new Map();

  increment(metric: string, labels: Record<string, string> = {}): void {
    const entries = this.counters.get(metric) ?? [];
    const existing = entries.find((e) => this.labelsMatch(e.labels, labels));
    if (existing) {
      existing.value++;
    } else {
      entries.push({ value: 1, labels });
    }
    this.counters.set(metric, entries);
  }

  observe(metric: string, value: number, labels: Record<string, string> = {}): void {
    const entries = this.histograms.get(metric) ?? [];
    entries.push({ value, labels });
    this.histograms.set(metric, entries);
  }

  /**
   * Get counter value for a metric with optional label filter.
   */
  getCounter(metric: string, labels?: Record<string, string>): number {
    const entries = this.counters.get(metric) ?? [];
    if (!labels) {
      return entries.reduce((sum, e) => sum + e.value, 0);
    }
    const match = entries.find((e) => this.labelsMatch(e.labels, labels));
    return match?.value ?? 0;
  }

  /**
   * Get histogram observations for a metric.
   */
  getHistogram(metric: string): number[] {
    const entries = this.histograms.get(metric) ?? [];
    return entries.map((e) => e.value);
  }

  /**
   * Reset all metrics.
   */
  reset(): void {
    this.counters.clear();
    this.histograms.clear();
  }

  /**
   * Export metrics as a simple object (for testing/debugging).
   */
  export(): Record<string, unknown> {
    const result: Record<string, unknown> = {};
    for (const [name, entries] of this.counters) {
      result[name] = entries;
    }
    for (const [name, entries] of this.histograms) {
      result[`${name}_observations`] = entries;
    }
    return result;
  }

  private labelsMatch(
    a: Record<string, string>,
    b: Record<string, string>,
  ): boolean {
    const keysA = Object.keys(a);
    const keysB = Object.keys(b);
    if (keysA.length !== keysB.length) return false;
    return keysA.every((key) => a[key] === b[key]);
  }
}
