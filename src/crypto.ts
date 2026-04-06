import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_LEN = 32;
const SALT_LEN = 16;
const IV_LEN = 16;
const TAG_LEN = 16;
const PBKDF2_ITER = 200_000;
const PBKDF2_DIGEST = 'sha256';

// Derive a stable AES key from the master secret + a fixed salt stored alongside the DB.
// For per-value encryption we use a fresh IV each time (stored with ciphertext).
export function deriveKey(masterSecret: string, salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(masterSecret, salt, PBKDF2_ITER, KEY_LEN, PBKDF2_DIGEST);
}

export function generateSalt(): Buffer {
  return crypto.randomBytes(SALT_LEN);
}

/**
 * Encrypts plaintext with AES-256-GCM.
 * Returns a base64 string: salt(16) | iv(16) | authTag(16) | ciphertext
 */
export function encrypt(plaintext: string, masterSecret: string): string {
  const salt = generateSalt();
  const key = deriveKey(masterSecret, salt);
  const iv = crypto.randomBytes(IV_LEN);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const result = Buffer.concat([salt, iv, authTag, encrypted]);
  return result.toString('base64');
}

/**
 * Decrypts a value produced by encrypt().
 */
export function decrypt(cipherb64: string, masterSecret: string): string {
  const buf = Buffer.from(cipherb64, 'base64');
  const salt = buf.subarray(0, SALT_LEN);
  const iv = buf.subarray(SALT_LEN, SALT_LEN + IV_LEN);
  const authTag = buf.subarray(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + TAG_LEN);
  const ciphertext = buf.subarray(SALT_LEN + IV_LEN + TAG_LEN);

  const key = deriveKey(masterSecret, salt);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  return decipher.update(ciphertext) + decipher.final('utf8');
}
