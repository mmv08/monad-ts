import { BaseError, type Hash } from "viem";

export type EncryptedTransactionErrorCode =
  | "invalidInput"
  | "unsupportedSigner"
  | "unavailable"
  | "rejected"
  | "unknownOutcome";

/** An ETX-specific failure. On a failed submission, `hash` identifies the attempted send. */
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
