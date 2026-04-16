type Labels = Record<string, string | number | boolean>;

type Counter = {
  name: string;
  help: string;
  value: number;
  labels: Labels;
};

const counters = new Map<string, Counter>();

function normalizeLabels(labels: Labels = {}): Labels {
  const out: Labels = {};
  for (const [k, v] of Object.entries(labels)) {
    out[k] = String(v);
  }
  return out;
}

function metricKey(name: string, labels: Labels): string {
  const sorted = Object.keys(labels)
    .sort()
    .map((key) => `${key}=${labels[key]}`)
    .join(',');
  return `${name}|${sorted}`;
}

export function incCounter(name: string, help: string, value = 1, labels: Labels = {}): void {
  const safeLabels = normalizeLabels(labels);
  const key = metricKey(name, safeLabels);
  const existing = counters.get(key);
  if (existing) {
    existing.value += value;
    return;
  }
  counters.set(key, {
    name,
    help,
    value,
    labels: safeLabels,
  });
}

function formatPromLabels(labels: Labels): string {
  const keys = Object.keys(labels);
  if (!keys.length) return '';
  const body = keys
    .sort()
    .map((key) => `${key}="${String(labels[key]).replace(/"/g, '\\"')}"`)
    .join(',');
  return `{${body}}`;
}

export function renderPrometheus(): string {
  const lines: string[] = [];
  const ordered = [...counters.values()].sort((a, b) => a.name.localeCompare(b.name));
  const emitted = new Set<string>();

  for (const metric of ordered) {
    if (!emitted.has(metric.name)) {
      lines.push(`# HELP ${metric.name} ${metric.help}`);
      lines.push(`# TYPE ${metric.name} counter`);
      emitted.add(metric.name);
    }
    lines.push(`${metric.name}${formatPromLabels(metric.labels)} ${metric.value}`);
  }

  return `${lines.join('\n')}\n`;
}

export function renderOtelJson(): Record<string, unknown> {
  return {
    resource: {
      service: {
        name: 'nexus-vault',
      },
    },
    generatedAt: new Date().toISOString(),
    metrics: [...counters.values()].map((counter) => ({
      name: counter.name,
      description: counter.help,
      unit: '1',
      type: 'counter',
      value: counter.value,
      attributes: counter.labels,
    })),
  };
}

export function getMetricsSnapshot(): Array<{ name: string; value: number; labels: Labels }> {
  return [...counters.values()].map((counter) => ({
    name: counter.name,
    value: counter.value,
    labels: counter.labels,
  }));
}

export function resetMetricsForTests(): void {
  counters.clear();
}
