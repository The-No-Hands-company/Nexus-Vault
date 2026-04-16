import nodemailer from 'nodemailer';

function envFlag(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const normalized = raw.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

let cachedTransporter: nodemailer.Transporter | null = null;

function getTransporter(): nodemailer.Transporter | null {
  if (cachedTransporter) return cachedTransporter;

  const host = process.env.VAULT_SMTP_HOST?.trim();
  const port = parseInt(process.env.VAULT_SMTP_PORT ?? '587', 10);
  const secure = envFlag('VAULT_SMTP_SECURE', false);
  const user = process.env.VAULT_SMTP_USER?.trim();
  const pass = process.env.VAULT_SMTP_PASS?.trim();

  if (!host) return null;

  cachedTransporter = nodemailer.createTransport({
    host,
    port: Number.isFinite(port) ? port : 587,
    secure,
    auth: user && pass ? { user, pass } : undefined,
  });

  return cachedTransporter;
}

export async function sendAuditFailureEmail(to: string, subject: string, text: string): Promise<boolean> {
  const transporter = getTransporter();
  const from = process.env.VAULT_SMTP_FROM?.trim();

  if (!transporter || !from) {
    console.warn('[vault:mail] Email transport not configured (set VAULT_SMTP_HOST and VAULT_SMTP_FROM)');
    return false;
  }

  try {
    await transporter.sendMail({
      from,
      to,
      subject,
      text,
    });
    console.log(`[vault:mail] Alert email sent to ${to}`);
    return true;
  } catch (err) {
    console.error('[vault:mail] Failed to send alert email:', err instanceof Error ? err.message : String(err));
    return false;
  }
}

export function _resetMailerForTests(): void {
  cachedTransporter = null;
}
