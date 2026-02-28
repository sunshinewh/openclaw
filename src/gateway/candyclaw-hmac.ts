import { createHmac, timingSafeEqual } from "node:crypto";

export type CandyclawHmacInput = {
  /** Value of x-candyclaw-ts param (millisecond timestamp). */
  timestamp: number | undefined;
  /** Value of x-candyclaw-nonce param (hex nonce for replay protection). */
  nonce: string | undefined;
  /** Value of x-candyclaw-sig param (hex HMAC-SHA256 signature). */
  signature: string | undefined;
  /** The raw message body that was signed. */
  messageBody: string;
  /** Base64-encoded HMAC shared key from gateway config. */
  sharedKeyBase64: string;
};

export type CandyclawHmacResult = {
  ok: boolean;
  reason:
    | "ok"
    | "no_key"
    | "missing_headers"
    | "timestamp_stale"
    | "nonce_reused"
    | "signature_mismatch";
};

/** Default maximum allowed age of a signed message (30 seconds). */
export const DEFAULT_TIMESTAMP_WINDOW_MS = 30_000;

/**
 * In-memory nonce tracker for replay protection.
 * Stores nonce → timestamp mappings and periodically prunes expired entries.
 */
export class NonceTracker {
  private seen = new Map<string, number>();
  private pruneIntervalMs: number;
  private lastPruneMs = 0;

  constructor(pruneIntervalMs = 60_000) {
    this.pruneIntervalMs = pruneIntervalMs;
  }

  /** Returns true if this nonce has been seen before (replay). */
  isDuplicate(nonce: string): boolean {
    this.maybePrune();
    return this.seen.has(nonce);
  }

  /** Record a nonce as used. */
  record(nonce: string, timestampMs: number): void {
    this.seen.set(nonce, timestampMs);
  }

  /** Remove nonces older than 2x the given timestamp window. */
  private maybePrune(timestampWindowMs = DEFAULT_TIMESTAMP_WINDOW_MS): void {
    const now = Date.now();
    if (now - this.lastPruneMs < this.pruneIntervalMs) {
      return;
    }
    this.lastPruneMs = now;
    const cutoff = now - timestampWindowMs * 2;
    for (const [nonce, ts] of this.seen) {
      if (ts < cutoff) {
        this.seen.delete(nonce);
      }
    }
  }

  /** Number of tracked nonces (for testing). */
  get size(): number {
    return this.seen.size;
  }
}

/** Singleton nonce tracker for the gateway process. */
export const globalNonceTracker = new NonceTracker();

/**
 * Verify a CandyClaw HMAC signature with nonce replay protection.
 *
 * Signing format: `v1|<timestamp>|<nonce>|<messageBody>`
 * This must match the Flutter SecureChannelService.signMessage() format.
 */
export function verifyCandyclawHmac(
  input: CandyclawHmacInput,
  nonceTracker: NonceTracker = globalNonceTracker,
  timestampWindowMs: number = DEFAULT_TIMESTAMP_WINDOW_MS,
): CandyclawHmacResult {
  const { timestamp, nonce, signature, messageBody, sharedKeyBase64 } = input;

  // Missing required fields.
  if (timestamp == null || !signature) {
    return { ok: false, reason: "missing_headers" };
  }

  // Timestamp freshness check.
  const now = Date.now();
  const age = Math.abs(now - timestamp);
  if (age > timestampWindowMs) {
    return { ok: false, reason: "timestamp_stale" };
  }

  // Nonce replay check (only when nonce is provided).
  if (nonce) {
    if (nonceTracker.isDuplicate(nonce)) {
      return { ok: false, reason: "nonce_reused" };
    }
  }

  // Reconstruct the signing payload (must match Flutter format).
  // Format with nonce: v1|timestamp|nonce|body
  // Format without nonce (legacy): v1|timestamp|body
  const dataToSign = nonce
    ? `v1|${timestamp}|${nonce}|${messageBody}`
    : `v1|${timestamp}|${messageBody}`;

  // Compute expected HMAC.
  const keyBytes = Buffer.from(sharedKeyBase64, "base64");
  const expectedHex = createHmac("sha256", keyBytes).update(dataToSign).digest("hex");

  // Constant-time comparison to prevent timing attacks.
  const expectedBuf = Buffer.from(expectedHex, "utf8");
  const providedBuf = Buffer.from(signature, "utf8");

  if (expectedBuf.length !== providedBuf.length) {
    return { ok: false, reason: "signature_mismatch" };
  }

  if (!timingSafeEqual(expectedBuf, providedBuf)) {
    return { ok: false, reason: "signature_mismatch" };
  }

  // Record the nonce after successful verification.
  if (nonce) {
    nonceTracker.record(nonce, timestamp);
  }

  return { ok: true, reason: "ok" };
}
