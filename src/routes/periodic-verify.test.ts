import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  performVerification,
  getLastVerificationResult,
  startPeriodicVerification,
  stopPeriodicVerification,
  _resetVerificationResult,
} from '../periodic-verify.js';

// Mock db functions
const {
  recordAuditVerificationRunMock,
  getLastAuditVerificationRunMock,
  sendAuditFailureEmailMock,
} = vi.hoisted(() => ({
  recordAuditVerificationRunMock: vi.fn(),
  getLastAuditVerificationRunMock: vi.fn(() => null),
  sendAuditFailureEmailMock: vi.fn(async () => true),
}));

vi.mock('../db.js', () => ({
  getAuditChainStatus: vi.fn(() => ({
    totalEntries: 42,
    headId: 42,
    headHash: 'hash-abc123',
    genesisOk: true,
  })),
  verifyAuditChain: vi.fn(() => ({ ok: true })),
  recordAuditVerificationRun: recordAuditVerificationRunMock,
  getLastAuditVerificationRun: getLastAuditVerificationRunMock,
}));

vi.mock('../mail.js', () => ({
  sendAuditFailureEmail: sendAuditFailureEmailMock,
}));

describe('periodic-verify', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetVerificationResult();
    process.env.VAULT_PERIODIC_VERIFY_ENABLED = 'true';
    process.env.VAULT_PERIODIC_VERIFY_INTERVAL_HOURS = '24';
    delete process.env.VAULT_ALERT_WEBHOOK_URL;
    delete process.env.VAULT_ALERT_EMAIL;
    delete process.env.VAULT_ALERT_THROTTLE_MINUTES;
    getLastAuditVerificationRunMock.mockReturnValue(null);
  });

  it('should perform verification and return success result', async () => {
    const result = await performVerification();

    expect(result.ok).toBe(true);
    expect(result.status.totalEntries).toBe(42);
    expect(result.status.headId).toBe(42);
    expect(result.timestamp).toBeDefined();
    expect(typeof result.details).toBe('string');
    expect(recordAuditVerificationRunMock).toHaveBeenCalledTimes(1);
  });

  it('should store verification result accessible via getter', async () => {
    expect(getLastVerificationResult()).toBeNull();

    await performVerification();
    const lastResult = getLastVerificationResult();

    expect(lastResult).not.toBeNull();
    expect(lastResult?.ok).toBe(true);
    expect(lastResult?.status.totalEntries).toBe(42);
  });

  it('should include proper details in result', async () => {
    const result = await performVerification();

    expect(result.details).toContain('verified');
    expect(result.details).toContain('42');
  });

  it('should start periodic verification and return timer', () => {
    const timer = startPeriodicVerification();

    expect(timer).not.toBeNull();
    if (timer) clearInterval(timer);
  });

  it('should return null when periodic verification disabled', () => {
    process.env.VAULT_PERIODIC_VERIFY_ENABLED = 'false';
    const timer = startPeriodicVerification();

    expect(timer).toBeNull();
  });

  it('should stop periodic verification', () => {
    const timer = startPeriodicVerification();
    expect(() => stopPeriodicVerification(timer)).not.toThrow();
  });

  it('should handle disabled verification gracefully', () => {
    process.env.VAULT_PERIODIC_VERIFY_ENABLED = '0';
    const timer = startPeriodicVerification();

    expect(timer).toBeNull();
  });

  it('should parse interval hours from environment', () => {
    process.env.VAULT_PERIODIC_VERIFY_INTERVAL_HOURS = '12';
    const timer = startPeriodicVerification();

    expect(timer).not.toBeNull();
    if (timer) clearInterval(timer);
  });

  it('should throttle alerts when webhook configured', async () => {
    process.env.VAULT_ALERT_WEBHOOK_URL = 'https://example.com/webhook';
    process.env.VAULT_ALERT_THROTTLE_MINUTES = '1';
    const fetchMock = vi.fn(async () => ({ ok: true, status: 200, statusText: 'OK' }));
    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);

    const { verifyAuditChain } = await import('../db.js');
    vi.mocked(verifyAuditChain).mockReturnValueOnce({ ok: false, brokenAt: 10, expected: 'hash1', got: 'hash2' } as any);

    const result1 = await performVerification();
    expect(result1.ok).toBe(false);

    // Reset mock for second call
    vi.mocked(verifyAuditChain).mockReturnValueOnce({ ok: false, brokenAt: 10, expected: 'hash1', got: 'hash2' } as any);

    // Second failure should also happen (no throttling in this simple test)
    const result2 = await performVerification();
    expect(result2.ok).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });

  it('should capture broken chain details in failure result', async () => {
    const { verifyAuditChain } = await import('../db.js');
    vi.mocked(verifyAuditChain).mockReturnValueOnce({ ok: false, brokenAt: 15, expected: 'exp-hash', got: 'got-hash' } as any);

    const result = await performVerification();

    expect(result.ok).toBe(false);
    expect(result.details).toContain('failure');
    expect(result.details).toContain('15');
  });

  it('sends SMTP email alerts when VAULT_ALERT_EMAIL is configured', async () => {
    process.env.VAULT_ALERT_EMAIL = 'ops@example.com';
    const { verifyAuditChain } = await import('../db.js');
    vi.mocked(verifyAuditChain).mockReturnValueOnce({ ok: false, brokenAt: 9, expected: 'exp', got: 'got' } as any);

    const result = await performVerification();

    expect(result.ok).toBe(false);
    expect(sendAuditFailureEmailMock).toHaveBeenCalledTimes(1);
  });

});
