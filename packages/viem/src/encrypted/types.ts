import type {
  AccessList,
  Account,
  Address,
  Hash,
  Hex,
  LocalAccount,
  Transaction,
  TransactionReceipt,
} from "viem";

export type EncryptedField = "to" | "value" | "data" | "accessList";

export type EncryptionContext =
  | { available: true; epoch: bigint; encryptionKey: Hex }
  | { available: false; epoch: bigint; encryptionKey: null };

export type EncryptedWalletActionsOptions = {
  /** Supplies one coherent key/epoch snapshot instead of the internal context RPC. */
  contextProvider?: (parameters: {
    chainId: number;
    account: Address;
  }) => Promise<EncryptionContext>;
};

export type SendEncryptedTransactionParameters<
  account extends Account | undefined = undefined,
> = {
  gas: bigint;
  value?: bigint;
  accessList?: AccessList;
  nonce?: number;
  chainId?: number;
  maxFeePerGas?: bigint;
  maxPriorityFeePerGas?: bigint;
  encryptedFields?: readonly [EncryptedField, ...EncryptedField[]];
  paddedLength?: number;
  gasPrice?: never;
  blobs?: never;
  blobVersionedHashes?: never;
  maxFeePerBlobGas?: never;
  sidecars?: never;
  kzg?: never;
  from?: never;
  chain?: never;
  authorizationList?: never;
  type?: never;
  ciphertext?: never;
  epoch?: never;
} & ({ to: Address; data?: Hex } | { to: null; data: Hex }) &
  ([account] extends [LocalAccount]
    ? { account?: LocalAccount }
    : { account: LocalAccount });

export type SendEncryptedTransactionReturnType = Hash;

export type DecryptionStatus = "pending" | "succeeded" | "failed" | "unknown";

export type EncryptedTransaction = Omit<
  Extract<Transaction, { type: "eip1559" }>,
  "type"
> & {
  type: "encrypted";
  typeHex: "0x8";
  encrypted: true;
  epoch: bigint;
  encryptedFields: number;
  ciphertext: Hex;
  concealedFields: readonly EncryptedField[];
  decryptionStatus: DecryptionStatus;
};

export type EncryptedTransactionReceipt = Omit<TransactionReceipt, "type"> & {
  type: "encrypted";
} & (
    | { decryptionStatus: "succeeded"; failureReason?: string }
    | { decryptionStatus: "failed"; failureReason: string; status: "reverted" }
    | { decryptionStatus: "unknown"; failureReason?: string }
  );
