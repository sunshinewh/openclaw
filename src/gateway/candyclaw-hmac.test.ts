import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { verifyCandyclawHmac } from "./candyclaw-hmac.js";

// Test key: 32 random bytes base64-encoded.
const TEST_KEY_BASE64 = Buffer.from(
  "0123456789abcdef0123456789abcdef", // 32 bytes
).toString("base64");

function sign(timestamp: number, body: string, keyBase64 = TEST_KEY_BASE64): string {
  const dataToSign = `v1|${timestamp}|${body}`;
  const keyBytes = Buffer.from(keyBase64, "base64");
  return createHmac("sha256", keyBytes).update(dataToSign).digest("hex");
}

describe("verifyCandyclawHmac", () => {
  it("accepts a valid signature", () => {
    const now = Date.now();
    const body = "Hello agent";
    const sig = sign(now, body);

    const result = verifyCandyclawHmac({
      timestamp: now,
      signature: sig,
      messageBody: body,
      sharedKeyBase64: TEST_KEY_BASE64,
    });

    expect(result.ok).toBe(true);
    expect(result.reason).toBe("ok");
  });

  it("rejects missing timestamp", () => {
    const result = verifyCandyclawHmac({
      timestamp: undefined,
      signature: "abc",
      messageBody: "test",
      sharedKeyBase64: TEST_KEY_BASE64,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("missing_headers");
  });

  it("rejects missing signature", () => {
    const result = verifyCandyclawHmac({
      timestamp: Date.now(),
      signature: undefined,
      messageBody: "test",
      sharedKeyBase64: TEST_KEY_BASE64,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("missing_headers");
  });

  it("rejects empty signature", () => {
    const result = verifyCandyclawHmac({
      timestamp: Date.now(),
      signature: "",
      messageBody: "test",
      sharedKeyBase64: TEST_KEY_BASE64,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("missing_headers");
  });

  it("rejects stale timestamp (older than 30s)", () => {
    const staleTs = Date.now() - 31_000;
    const body = "test";
    const sig = sign(staleTs, body);

    const result = verifyCandyclawHmac({
      timestamp: staleTs,
      signature: sig,
      messageBody: body,
      sharedKeyBase64: TEST_KEY_BASE64,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("timestamp_stale");
  });

  it("rejects future timestamp beyond window", () => {
    const futureTs = Date.now() + 31_000;
    const body = "test";
    const sig = sign(futureTs, body);

    const result = verifyCandyclawHmac({
      timestamp: futureTs,
      signature: sig,
      messageBody: body,
      sharedKeyBase64: TEST_KEY_BASE64,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("timestamp_stale");
  });

  it("accepts timestamp within window boundary", () => {
    const ts = Date.now() - 29_000;
    const body = "test";
    const sig = sign(ts, body);

    const result = verifyCandyclawHmac({
      timestamp: ts,
      signature: sig,
      messageBody: body,
      sharedKeyBase64: TEST_KEY_BASE64,
    });

    expect(result.ok).toBe(true);
  });

  it("rejects tampered signature", () => {
    const now = Date.now();
    const body = "test";
    const sig = sign(now, body);
    const tampered = sig.replace(sig[0], sig[0] === "a" ? "b" : "a");

    const result = verifyCandyclawHmac({
      timestamp: now,
      signature: tampered,
      messageBody: body,
      sharedKeyBase64: TEST_KEY_BASE64,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("signature_mismatch");
  });

  it("rejects tampered message body", () => {
    const now = Date.now();
    const body = "original message";
    const sig = sign(now, body);

    const result = verifyCandyclawHmac({
      timestamp: now,
      signature: sig,
      messageBody: "modified message",
      sharedKeyBase64: TEST_KEY_BASE64,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("signature_mismatch");
  });

  it("rejects wrong key", () => {
    const now = Date.now();
    const body = "test";
    const sig = sign(now, body);
    const wrongKey = Buffer.from("ffffffffffffffffffffffffffffffff").toString("base64");

    const result = verifyCandyclawHmac({
      timestamp: now,
      signature: sig,
      messageBody: body,
      sharedKeyBase64: wrongKey,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("signature_mismatch");
  });

  it("handles message body with pipe characters (boundary edge case)", () => {
    const now = Date.now();
    const body = "12345|this|has|pipes";
    const sig = sign(now, body);

    const result = verifyCandyclawHmac({
      timestamp: now,
      signature: sig,
      messageBody: body,
      sharedKeyBase64: TEST_KEY_BASE64,
    });

    expect(result.ok).toBe(true);
  });

  it("handles empty message body", () => {
    const now = Date.now();
    const body = "";
    const sig = sign(now, body);

    const result = verifyCandyclawHmac({
      timestamp: now,
      signature: sig,
      messageBody: body,
      sharedKeyBase64: TEST_KEY_BASE64,
    });

    expect(result.ok).toBe(true);
  });

  it("rejects signature with wrong length", () => {
    const result = verifyCandyclawHmac({
      timestamp: Date.now(),
      signature: "tooshort",
      messageBody: "test",
      sharedKeyBase64: TEST_KEY_BASE64,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("signature_mismatch");
  });
});
