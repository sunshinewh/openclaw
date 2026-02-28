import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { NonceTracker, verifyCandyclawHmac } from "./candyclaw-hmac.js";

// Test key: 32 random bytes base64-encoded.
const TEST_KEY_BASE64 = Buffer.from(
  "0123456789abcdef0123456789abcdef", // 32 bytes
).toString("base64");

/** Sign without nonce (legacy format). */
function sign(timestamp: number, body: string, keyBase64 = TEST_KEY_BASE64): string {
  const dataToSign = `v1|${timestamp}|${body}`;
  const keyBytes = Buffer.from(keyBase64, "base64");
  return createHmac("sha256", keyBytes).update(dataToSign).digest("hex");
}

/** Sign with nonce (Phase 2 format). */
function signWithNonce(
  timestamp: number,
  nonce: string,
  body: string,
  keyBase64 = TEST_KEY_BASE64,
): string {
  const dataToSign = `v1|${timestamp}|${nonce}|${body}`;
  const keyBytes = Buffer.from(keyBase64, "base64");
  return createHmac("sha256", keyBytes).update(dataToSign).digest("hex");
}

describe("verifyCandyclawHmac", () => {
  it("accepts a valid signature without nonce (legacy)", () => {
    const tracker = new NonceTracker();
    const now = Date.now();
    const body = "Hello agent";
    const sig = sign(now, body);

    const result = verifyCandyclawHmac(
      {
        timestamp: now,
        nonce: undefined,
        signature: sig,
        messageBody: body,
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );

    expect(result.ok).toBe(true);
    expect(result.reason).toBe("ok");
  });

  it("accepts a valid signature with nonce", () => {
    const tracker = new NonceTracker();
    const now = Date.now();
    const body = "Hello agent";
    const nonce = "abc123def456";
    const sig = signWithNonce(now, nonce, body);

    const result = verifyCandyclawHmac(
      {
        timestamp: now,
        nonce,
        signature: sig,
        messageBody: body,
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );

    expect(result.ok).toBe(true);
    expect(result.reason).toBe("ok");
  });

  it("rejects missing timestamp", () => {
    const tracker = new NonceTracker();
    const result = verifyCandyclawHmac(
      {
        timestamp: undefined,
        nonce: undefined,
        signature: "abc",
        messageBody: "test",
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("missing_headers");
  });

  it("rejects missing signature", () => {
    const tracker = new NonceTracker();
    const result = verifyCandyclawHmac(
      {
        timestamp: Date.now(),
        nonce: undefined,
        signature: undefined,
        messageBody: "test",
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("missing_headers");
  });

  it("rejects stale timestamp (older than 30s)", () => {
    const tracker = new NonceTracker();
    const staleTs = Date.now() - 31_000;
    const body = "test";
    const sig = sign(staleTs, body);

    const result = verifyCandyclawHmac(
      {
        timestamp: staleTs,
        nonce: undefined,
        signature: sig,
        messageBody: body,
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("timestamp_stale");
  });

  it("accepts timestamp within window boundary", () => {
    const tracker = new NonceTracker();
    const ts = Date.now() - 29_000;
    const body = "test";
    const sig = sign(ts, body);

    const result = verifyCandyclawHmac(
      {
        timestamp: ts,
        nonce: undefined,
        signature: sig,
        messageBody: body,
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );

    expect(result.ok).toBe(true);
  });

  it("rejects tampered signature", () => {
    const tracker = new NonceTracker();
    const now = Date.now();
    const body = "test";
    const sig = sign(now, body);
    const tampered = sig.replace(sig[0], sig[0] === "a" ? "b" : "a");

    const result = verifyCandyclawHmac(
      {
        timestamp: now,
        nonce: undefined,
        signature: tampered,
        messageBody: body,
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("signature_mismatch");
  });

  it("rejects tampered message body", () => {
    const tracker = new NonceTracker();
    const now = Date.now();
    const body = "original message";
    const sig = sign(now, body);

    const result = verifyCandyclawHmac(
      {
        timestamp: now,
        nonce: undefined,
        signature: sig,
        messageBody: "modified message",
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("signature_mismatch");
  });

  it("rejects wrong key", () => {
    const tracker = new NonceTracker();
    const now = Date.now();
    const body = "test";
    const sig = sign(now, body);
    const wrongKey = Buffer.from("ffffffffffffffffffffffffffffffff").toString("base64");

    const result = verifyCandyclawHmac(
      {
        timestamp: now,
        nonce: undefined,
        signature: sig,
        messageBody: body,
        sharedKeyBase64: wrongKey,
      },
      tracker,
    );

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("signature_mismatch");
  });

  it("handles message body with pipe characters", () => {
    const tracker = new NonceTracker();
    const now = Date.now();
    const body = "12345|this|has|pipes";
    const sig = sign(now, body);

    const result = verifyCandyclawHmac(
      {
        timestamp: now,
        nonce: undefined,
        signature: sig,
        messageBody: body,
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );

    expect(result.ok).toBe(true);
  });

  it("handles empty message body", () => {
    const tracker = new NonceTracker();
    const now = Date.now();
    const body = "";
    const sig = sign(now, body);

    const result = verifyCandyclawHmac(
      {
        timestamp: now,
        nonce: undefined,
        signature: sig,
        messageBody: body,
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );

    expect(result.ok).toBe(true);
  });

  it("rejects signature with wrong length", () => {
    const tracker = new NonceTracker();
    const result = verifyCandyclawHmac(
      {
        timestamp: Date.now(),
        nonce: undefined,
        signature: "tooshort",
        messageBody: "test",
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("signature_mismatch");
  });
});

describe("NonceTracker", () => {
  it("reports duplicate nonce", () => {
    const tracker = new NonceTracker();
    tracker.record("nonce1", Date.now());
    expect(tracker.isDuplicate("nonce1")).toBe(true);
  });

  it("reports unique nonce", () => {
    const tracker = new NonceTracker();
    expect(tracker.isDuplicate("nonce1")).toBe(false);
  });

  it("tracks size", () => {
    const tracker = new NonceTracker();
    tracker.record("a", Date.now());
    tracker.record("b", Date.now());
    expect(tracker.size).toBe(2);
  });
});

describe("nonce replay protection", () => {
  it("rejects replayed nonce", () => {
    const tracker = new NonceTracker();
    const now = Date.now();
    const body = "test";
    const nonce = "unique-nonce-123";
    const sig = signWithNonce(now, nonce, body);

    // First use: should succeed.
    const first = verifyCandyclawHmac(
      {
        timestamp: now,
        nonce,
        signature: sig,
        messageBody: body,
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );
    expect(first.ok).toBe(true);

    // Replay: same nonce should fail.
    const replay = verifyCandyclawHmac(
      {
        timestamp: now,
        nonce,
        signature: sig,
        messageBody: body,
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );
    expect(replay.ok).toBe(false);
    expect(replay.reason).toBe("nonce_reused");
  });

  it("accepts different nonces for same message", () => {
    const tracker = new NonceTracker();
    const now = Date.now();
    const body = "same message";

    const sig1 = signWithNonce(now, "nonce-a", body);
    const sig2 = signWithNonce(now, "nonce-b", body);

    const r1 = verifyCandyclawHmac(
      {
        timestamp: now,
        nonce: "nonce-a",
        signature: sig1,
        messageBody: body,
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );
    const r2 = verifyCandyclawHmac(
      {
        timestamp: now,
        nonce: "nonce-b",
        signature: sig2,
        messageBody: body,
        sharedKeyBase64: TEST_KEY_BASE64,
      },
      tracker,
    );

    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
  });
});
