import { afterEach, describe, expect, it, vi } from 'vitest';

function captureStdout() {
  const chunks: string[] = [];
  const spy = vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: any) => {
    chunks.push(typeof chunk === 'string' ? chunk : String(chunk));
    return true;
  }) as any);

  return {
    chunks,
    restore: () => spy.mockRestore(),
  };
}

afterEach(() => {
  delete process.env.VAULT_LOG_FORMAT;
  delete process.env.VAULT_LOG_LEVEL;
  delete process.env.VAULT_LOG_REQUEST_BODY;
  delete process.env.VAULT_LOG_MAX_FIELD_CHARS;
  vi.restoreAllMocks();
});

describe('logger structured redaction', () => {
  it('redacts sensitive fields in JSON logs', async () => {
    process.env.VAULT_LOG_FORMAT = 'json';
    process.env.VAULT_LOG_LEVEL = 'debug';

    const { chunks, restore } = captureStdout();
    try {
      const { logger } = await import('./logger.js');
      logger.info('test.redaction', {
        authorization: 'Bearer secret-token',
        password: 'plaintext',
        nested: {
          refresh_token: 'refresh-secret',
          normal: 'kept',
        },
      });
    } finally {
      restore();
    }

    const line = chunks.find((c) => c.trim().startsWith('{'));
    expect(line).toBeTruthy();
    const parsed = JSON.parse(String(line).trim()) as Record<string, unknown>;
    expect(parsed.authorization).toBe('[REDACTED]');
    expect(parsed.password).toBe('[REDACTED]');
    expect(parsed.nested).toMatchObject({
      refresh_token: '[REDACTED]',
      normal: 'kept',
    });
  });
});
