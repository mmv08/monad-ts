import { hex, safeInteger, uint } from "./codec.js";
import { EncryptedTransactionError } from "./errors.js";
import type { EncryptionContext } from "./types.js";

export function quantity(value: unknown, bits: number): bigint {
  if (typeof value === "number") {
    safeInteger(value);
    value = BigInt(value);
  } else if (
    typeof value === "string" &&
    /^0x(?:0|[1-9a-fA-F][\da-fA-F]*)$/.test(value)
  ) {
    value = BigInt(value);
  }
  uint(value, bits);
  return value;
}

export function parseContext(value: unknown): EncryptionContext {
  try {
    if (
      !value ||
      typeof value !== "object" ||
      !("epoch" in value) ||
      !("available" in value) ||
      !("encryptionKey" in value)
    )
      throw new Error();
    const epoch = quantity(value.epoch, 64);
    if (value.available === false && value.encryptionKey === null)
      return { available: false, epoch, encryptionKey: null };
    if (value.available !== true) throw new Error();
    hex(value.encryptionKey, 576);
    return { available: true, epoch, encryptionKey: value.encryptionKey };
  } catch {
    throw new EncryptedTransactionError(
      "invalidContext",
      "Invalid encryption context.",
    );
  }
}
