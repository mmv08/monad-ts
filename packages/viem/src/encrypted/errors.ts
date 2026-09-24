import { BaseError, type Hash } from "viem";

export type EncryptedTransactionErrorCode =
  | "invalidInput"
  | "invalidContext"
  | "unavailable"
  | "unsupportedSigner"
  | "unsupportedTransport"
  | "invalidResponse"
  | "rejected"
  | "expiredEpoch"
  | "unknownOutcome";

/** An ETX-specific failure. A hash on unknownOutcome identifies the attempted send. */
export class EncryptedTransactionError extends BaseError {
  readonly code: EncryptedTransactionErrorCode;
  readonly hash?: Hash;

  constructor(
    code: EncryptedTransactionErrorCode,
    message: string,
    options: { cause?: Error; hash?: Hash } = {},
  ) {
    super(message, { cause: options.cause, name: "EncryptedTransactionError" });
    this.code = code;
    this.hash = options.hash;
  }
}

export function assertInput(
  condition: unknown,
  message: string,
): asserts condition {
  if (!condition) throw new EncryptedTransactionError("invalidInput", message);
}
