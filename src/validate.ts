import { VAULT_ENTRY_TYPES, VAULT_CATEGORIES, isVaultEntryType, isVaultCategory } from './db.js';
import type { VaultEntryType, VaultCategory } from './db.js';

export type ValidationError = { field: string; message: string };

export type ValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; errors: ValidationError[] };

// ── Primitive validators ──────────────────────────────────────────────────────

export function validateString(
  raw: unknown,
  field: string,
  opts: { required?: boolean; maxLen?: number; minLen?: number; pattern?: RegExp } = {},
): ValidationError | null {
  if (raw === undefined || raw === null || raw === '') {
    return opts.required ? { field, message: `${field} is required` } : null;
  }
  const v = String(raw);
  if (opts.minLen !== undefined && v.length < opts.minLen) {
    return { field, message: `${field} must be at least ${opts.minLen} characters` };
  }
  if (opts.maxLen !== undefined && v.length > opts.maxLen) {
    return { field, message: `${field} must be at most ${opts.maxLen} characters` };
  }
  if (opts.pattern && !opts.pattern.test(v)) {
    return { field, message: `${field} contains invalid characters` };
  }
  return null;
}

export function validateDate(raw: unknown, field: string): ValidationError | null {
  if (raw === undefined || raw === null || raw === '') return null;
  const v = String(raw);
  if (!/^\d{4}-\d{2}-\d{2}(T[\d:.Z+-]+)?$/.test(v) || isNaN(Date.parse(v))) {
    return { field, message: `${field} must be a valid ISO date (YYYY-MM-DD)` };
  }
  return null;
}

// ── Domain validators ─────────────────────────────────────────────────────────

/** Validates an entry name — printable ASCII, no path separators, max 200 chars */
export function validateEntryName(raw: unknown): ValidationError | null {
  const base = validateString(raw, 'name', {
    required: true,
    minLen: 1,
    maxLen: 200,
    // Allow alphanumeric, dots, dashes, underscores, slashes (for namespaced keys)
    pattern: /^[A-Za-z0-9_./:@-]+$/,
  });
  return base;
}

/** Validates a collection name — same rules as entry name */
export function validateCollectionName(raw: unknown, field = 'name'): ValidationError | null {
  return validateString(raw, field, {
    required: true,
    minLen: 1,
    maxLen: 200,
    pattern: /^[A-Za-z0-9_./:-]+$/,
  });
}

export function validateEntryType(raw: unknown): { value: VaultEntryType } | ValidationError {
  if (!isVaultEntryType(raw)) {
    return { field: 'type', message: `type must be one of: ${VAULT_ENTRY_TYPES.join(', ')}` };
  }
  return { value: raw };
}

export function validateCategory(raw: unknown): { value: VaultCategory } | ValidationError {
  if (!isVaultCategory(raw)) {
    return { field: 'category', message: `category must be one of: ${VAULT_CATEGORIES.join(', ')}` };
  }
  return { value: raw };
}

// ── Composite validators ──────────────────────────────────────────────────────

export interface CreateEntryInput {
  name: string;
  value: string;
  type?: VaultEntryType;
  category?: VaultCategory;
  collection?: string | null;
  project?: string;
  notes?: string;
  tags?: unknown;
  metadata?: unknown;
  expires_at?: string | null;
}

export function validateCreateEntry(body: Record<string, unknown>): ValidationResult<CreateEntryInput> {
  const errors: ValidationError[] = [];

  const nameErr = validateEntryName(body.name);
  if (nameErr) errors.push(nameErr);

  if (body.value === undefined || body.value === null || body.value === '') {
    errors.push({ field: 'value', message: 'value is required' });
  } else {
    const valueErr = validateString(body.value, 'value', { maxLen: 32768 });
    if (valueErr) errors.push(valueErr);
  }

  if (body.type !== undefined && !isVaultEntryType(body.type)) {
    errors.push({ field: 'type', message: `type must be one of: ${VAULT_ENTRY_TYPES.join(', ')}` });
  }
  if (body.category !== undefined && !isVaultCategory(body.category)) {
    errors.push({ field: 'category', message: `category must be one of: ${VAULT_CATEGORIES.join(', ')}` });
  }

  const collErr = body.collection
    ? validateString(body.collection, 'collection', { maxLen: 200 })
    : null;
  if (collErr) errors.push(collErr);

  const projErr = validateString(body.project, 'project', { maxLen: 200 });
  if (projErr) errors.push(projErr);

  const notesErr = validateString(body.notes, 'notes', { maxLen: 4000 });
  if (notesErr) errors.push(notesErr);

  if (body.tags !== undefined && body.tags !== null) {
    if (!Array.isArray(body.tags)) {
      errors.push({ field: 'tags', message: 'tags must be an array of strings' });
    } else if (body.tags.length > 50) {
      errors.push({ field: 'tags', message: 'tags must contain at most 50 items' });
    } else if (body.tags.some((t) => typeof t !== 'string')) {
      errors.push({ field: 'tags', message: 'tags must be an array of strings' });
    }
  }

  if (body.metadata !== undefined && body.metadata !== null) {
    try {
      const metaStr = typeof body.metadata === 'string' ? body.metadata : JSON.stringify(body.metadata);
      if (metaStr.length > 16384) {
        errors.push({ field: 'metadata', message: 'metadata must not exceed 16KB when serialized' });
      }
    } catch {
      errors.push({ field: 'metadata', message: 'metadata must be a valid JSON object or string' });
    }
  }

  const dateErr = validateDate(body.expires_at, 'expires_at');
  if (dateErr) errors.push(dateErr);

  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    value: {
      name: String(body.name).trim(),
      value: String(body.value),
      type: isVaultEntryType(body.type) ? body.type : undefined,
      category: isVaultCategory(body.category) ? body.category : undefined,
      collection: body.collection ? String(body.collection) : null,
      project: body.project ? String(body.project) : '',
      notes: body.notes ? String(body.notes) : '',
      tags: body.tags,
      metadata: body.metadata,
      expires_at: body.expires_at ? String(body.expires_at) : null,
    },
  };
}

export interface UpdateEntryInput {
  value?: string;
  type?: VaultEntryType;
  category?: VaultCategory;
  collection?: string | null;
  project?: string;
  notes?: string;
  tags?: unknown;
  metadata?: unknown;
  expires_at?: string | null;
}

export function validateUpdateEntry(body: Record<string, unknown>): ValidationResult<UpdateEntryInput> {
  const errors: ValidationError[] = [];

  if (body.value !== undefined && (body.value === null || body.value === '')) {
    errors.push({ field: 'value', message: 'value cannot be set to empty on update' });
  } else if (body.value !== undefined) {
    const valueErr = validateString(body.value, 'value', { maxLen: 32768 });
    if (valueErr) errors.push(valueErr);
  }

  if (body.type !== undefined && !isVaultEntryType(body.type)) {
    errors.push({ field: 'type', message: `type must be one of: ${VAULT_ENTRY_TYPES.join(', ')}` });
  }
  if (body.category !== undefined && !isVaultCategory(body.category)) {
    errors.push({ field: 'category', message: `category must be one of: ${VAULT_CATEGORIES.join(', ')}` });
  }

  const projErr = body.project !== undefined ? validateString(body.project, 'project', { maxLen: 200 }) : null;
  if (projErr) errors.push(projErr);

  const notesErr = body.notes !== undefined ? validateString(body.notes, 'notes', { maxLen: 4000 }) : null;
  if (notesErr) errors.push(notesErr);

  if (body.tags !== undefined && body.tags !== null) {
    if (!Array.isArray(body.tags)) {
      errors.push({ field: 'tags', message: 'tags must be an array of strings' });
    } else if (body.tags.length > 50) {
      errors.push({ field: 'tags', message: 'tags must contain at most 50 items' });
    } else if (body.tags.some((t) => typeof t !== 'string')) {
      errors.push({ field: 'tags', message: 'tags must be an array of strings' });
    }
  }

  if (body.metadata !== undefined && body.metadata !== null) {
    try {
      const metaStr = typeof body.metadata === 'string' ? body.metadata : JSON.stringify(body.metadata);
      if (metaStr.length > 16384) {
        errors.push({ field: 'metadata', message: 'metadata must not exceed 16KB when serialized' });
      }
    } catch {
      errors.push({ field: 'metadata', message: 'metadata must be a valid JSON object or string' });
    }
  }

  const dateErr = validateDate(body.expires_at, 'expires_at');
  if (dateErr) errors.push(dateErr);

  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    value: {
      value: body.value !== undefined ? String(body.value) : undefined,
      type: isVaultEntryType(body.type) ? body.type : undefined,
      category: isVaultCategory(body.category) ? body.category : undefined,
      collection: body.collection !== undefined ? (body.collection ? String(body.collection) : null) : undefined,
      project: body.project !== undefined ? String(body.project) : undefined,
      notes: body.notes !== undefined ? String(body.notes) : undefined,
      tags: body.tags,
      metadata: body.metadata,
      expires_at: body.expires_at === undefined ? undefined : (body.expires_at ? String(body.expires_at) : null),
    },
  };
}

export interface CreateCollectionInput {
  name: string;
  description?: string;
  parentName?: string | null;
  icon?: string;
  color?: string;
}

export function validateCreateCollection(body: Record<string, unknown>): ValidationResult<CreateCollectionInput> {
  const errors: ValidationError[] = [];

  const nameErr = validateCollectionName(body.name);
  if (nameErr) errors.push(nameErr);

  const descErr = validateString(body.description, 'description', { maxLen: 500 });
  if (descErr) errors.push(descErr);

  const iconErr = validateString(body.icon, 'icon', { maxLen: 50 });
  if (iconErr) errors.push(iconErr);

  const colorErr = validateString(body.color, 'color', { maxLen: 50 });
  if (colorErr) errors.push(colorErr);

  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    value: {
      name: String(body.name).trim(),
      description: body.description ? String(body.description) : '',
      parentName: body.parentName ? String(body.parentName) : null,
      icon: body.icon ? String(body.icon) : 'folder',
      color: body.color ? String(body.color) : 'slate',
    },
  };
}

export interface ImportEnvInput {
  env: string;
  collection?: string | null;
  project?: string;
  tags?: string[];
  namePrefix?: string;
}

export function validateImportEnv(body: Record<string, unknown>): ValidationResult<ImportEnvInput> {
  const errors: ValidationError[] = [];

  const envErr = validateString(body.env, 'env', { required: true, maxLen: 1_000_000 });
  if (envErr) errors.push(envErr);

  if (body.collection !== undefined && body.collection !== null && body.collection !== '') {
    const collErr = validateCollectionName(body.collection, 'collection');
    if (collErr) errors.push(collErr);
  }

  const projectErr = validateString(body.project, 'project', { maxLen: 200 });
  if (projectErr) errors.push(projectErr);

  const prefixErr = validateString(body.namePrefix, 'namePrefix', { maxLen: 100, pattern: /^[A-Za-z0-9_./:@-]*$/ });
  if (prefixErr) errors.push(prefixErr);

  if (body.tags !== undefined) {
    if (!Array.isArray(body.tags) || body.tags.some((t) => typeof t !== 'string')) {
      errors.push({ field: 'tags', message: 'tags must be an array of strings' });
    }
  }

  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    value: {
      env: String(body.env ?? ''),
      collection: body.collection ? String(body.collection) : null,
      project: body.project ? String(body.project) : '',
      tags: Array.isArray(body.tags) ? body.tags.map((t) => String(t).trim()).filter(Boolean) : undefined,
      namePrefix: body.namePrefix ? String(body.namePrefix) : '',
    },
  };
}

export interface OpenClawPluginInput {
  name: string;
  icon?: string;
  env?: string[];
  config?: string[];
  bins?: string[];
  anyBins?: string[];
  os?: string | null;
}

export interface ImportOpenClawInput {
  plugins: OpenClawPluginInput[];
  values: Record<string, string>;
  project: string;
  includePlaceholders: boolean;
}

export function validateImportOpenClaw(body: Record<string, unknown>): ValidationResult<ImportOpenClawInput> {
  const errors: ValidationError[] = [];
  const plugins = Array.isArray(body.plugins) ? body.plugins : [];

  if (!plugins.length) {
    errors.push({ field: 'plugins', message: 'plugins must be a non-empty array' });
  }

  const parsedPlugins: OpenClawPluginInput[] = [];
  for (let i = 0; i < plugins.length; i++) {
    const p = plugins[i];
    if (!p || typeof p !== 'object') {
      errors.push({ field: `plugins[${i}]`, message: 'plugin must be an object' });
      continue;
    }
    const plugin = p as Record<string, unknown>;
    const nameErr = validateString(plugin.name, `plugins[${i}].name`, {
      required: true,
      maxLen: 120,
      pattern: /^[A-Za-z0-9._-]+$/,
    });
    if (nameErr) {
      errors.push(nameErr);
      continue;
    }

    const parseStringArray = (raw: unknown, field: string): string[] | null => {
      if (raw === undefined) return [];
      if (!Array.isArray(raw) || raw.some((x) => typeof x !== 'string')) {
        errors.push({ field, message: `${field} must be an array of strings` });
        return null;
      }
      return raw.map((x) => String(x)).map((x) => x.trim()).filter(Boolean);
    };

    const env = parseStringArray(plugin.env, `plugins[${i}].env`);
    const config = parseStringArray(plugin.config, `plugins[${i}].config`);
    const bins = parseStringArray(plugin.bins, `plugins[${i}].bins`);
    const anyBins = parseStringArray(plugin.anyBins, `plugins[${i}].anyBins`);

    parsedPlugins.push({
      name: String(plugin.name),
      icon: plugin.icon ? String(plugin.icon) : undefined,
      env: env ?? [],
      config: config ?? [],
      bins: bins ?? [],
      anyBins: anyBins ?? [],
      os: plugin.os === null || plugin.os === undefined ? null : String(plugin.os),
    });
  }

  let values: Record<string, string> = {};
  if (body.values !== undefined) {
    if (!body.values || typeof body.values !== 'object' || Array.isArray(body.values)) {
      errors.push({ field: 'values', message: 'values must be an object map of string keys and values' });
    } else {
      const result: Record<string, string> = {};
      for (const [k, v] of Object.entries(body.values as Record<string, unknown>)) {
        if (typeof v !== 'string') {
          errors.push({ field: `values.${k}`, message: 'value must be a string' });
          continue;
        }
        result[k] = v;
      }
      values = result;
    }
  }

  const projectErr = validateString(body.project, 'project', { maxLen: 200 });
  if (projectErr) errors.push(projectErr);

  if (body.includePlaceholders !== undefined && typeof body.includePlaceholders !== 'boolean') {
    errors.push({ field: 'includePlaceholders', message: 'includePlaceholders must be a boolean' });
  }

  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    value: {
      plugins: parsedPlugins,
      values,
      project: body.project ? String(body.project) : 'openclaw',
      includePlaceholders: body.includePlaceholders === true,
    },
  };
}

export interface ImportDocumentInput {
  version: number;
  collections: Array<Record<string, unknown>>;
  entries: Array<Record<string, unknown>>;
  replaceExisting: boolean;
}

export function validateImportDocument(body: Record<string, unknown>): ValidationResult<ImportDocumentInput> {
  const errors: ValidationError[] = [];
  if (body.version !== 1) {
    errors.push({ field: 'version', message: 'Unsupported import version' });
  }

  const collections = Array.isArray(body.collections) ? body.collections : [];
  const entries = Array.isArray(body.entries) ? body.entries : [];

  for (let i = 0; i < collections.length; i++) {
    const c = collections[i];
    if (!c || typeof c !== 'object') {
      errors.push({ field: `collections[${i}]`, message: 'collection must be an object' });
      continue;
    }
    const nameErr = validateCollectionName((c as Record<string, unknown>).name, `collections[${i}].name`);
    if (nameErr) errors.push(nameErr);
  }

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (!e || typeof e !== 'object') {
      errors.push({ field: `entries[${i}]`, message: 'entry must be an object' });
      continue;
    }
    const item = e as Record<string, unknown>;
    const nameErr = validateEntryName(item.name);
    if (nameErr) errors.push({ field: `entries[${i}].name`, message: nameErr.message });
    if (item.value === undefined || item.value === null) {
      errors.push({ field: `entries[${i}].value`, message: 'value is required' });
    }
  }

  if (body.replaceExisting !== undefined && typeof body.replaceExisting !== 'boolean') {
    errors.push({ field: 'replaceExisting', message: 'replaceExisting must be a boolean' });
  }

  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    value: {
      version: 1,
      collections: collections.filter((c): c is Record<string, unknown> => !!c && typeof c === 'object'),
      entries: entries.filter((e): e is Record<string, unknown> => !!e && typeof e === 'object'),
      replaceExisting: body.replaceExisting === true,
    },
  };
}

// ── Response helper ───────────────────────────────────────────────────────────

import type { Response } from 'express';

export function sendValidationError(res: Response, errors: ValidationError[]): void {
  res.status(400).json({ error: 'Validation failed', details: errors });
}
