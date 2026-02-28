import { createHmac, timingSafeEqual } from "node:crypto";

export type CandyclawHmacInput = {
  /** Value of x-candyclaw-ts param (millisecond timestamp). */
  timestamp: number | undefined;
  /** Value of x-candyclaw-sig param (hex HMAC-SHA256 signature). */
  signature: string | undefined;
  /** The raw message body that was signed. */
  messageBody: string;
  /** Base64-encoded HMAC shared key from gateway config. */
  sharedKeyBase64: string;
};

export type CandyclawHmacResult = {
  ok: boolean;
  reason: "ok" | "no_key" | "missing_headers" | "timestamp_stale" | "signature_mismatch";
};

/** Maximum allowed age of a signed message (30 seconds). */
const TIMESTAMP_WINDOW_MS = 30_000;

/**
 * Verify a CandyClaw HMAC signature.
 *
 * Signing format: `v1|<timestamp>|<messageBody>`
 * This must match the Flutter SecureChannelService.signMessage() format.
 */
export function verifyCandyclawHmac(input: CandyclawHmacInput): CandyclawHmacResult {
  const { timestamp, signature, messageBody, sharedKeyBase64 } = input;

  // Missing required fields.
  if (timestamp == null || !signature) {
    return { ok: false, reason: "missing_headers" };
  }

  // Timestamp freshness check.
  const now = Date.now();
  const age = Math.abs(now - timestamp);
  if (age > TIMESTAMP_WINDOW_MS) {
    return { ok: false, reason: "timestamp_stale" };
  }

  // Reconstruct the signing payload (must match Flutter format).
  const dataToSign = `v1|${timestamp}|${messageBody}`;

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

  return { ok: true, reason: "ok" };
}
