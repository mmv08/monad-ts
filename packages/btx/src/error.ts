/** The rejection reasons named by the BTX specification. */
type BtxErrorCode =
  | "InvalidLength"
  | "InvalidPoint"
  | "InvalidScalar"
  | "InvalidCiphertext"
  | "ClientNizkFailed";

/** A key, ciphertext, or proof that the BTX specification rejects. */
class BtxError extends Error {
  override readonly name = "BtxError";

  constructor(
    readonly code: BtxErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
  }
}

export type { BtxErrorCode };
export { BtxError };
