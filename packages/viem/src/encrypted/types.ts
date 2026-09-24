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
import type { fields } from "./codec.js";

export type EncryptedField = (typeof fields)[number];

/** One key/epoch snapshot. The RPC form carries a hex epoch, as viem's Rpc* types do. */
export type EncryptionContext<quantity = bigint> =
  | { available: true; epoch: quantity; encryptionKey: Hex }
  | { available: false; epoch: quantity; encryptionKey: null };

export type EncryptedWalletActionsParameters = {
  /** Supplies one coherent key/epoch snapshot instead of the internal context RPC. */
  contextProvider?:
    | ((parameters: {
        chainId: number;
        account: Address;
      }) => Promise<EncryptionContext>)
    | undefined;
};

export type SendEncryptedTransactionParameters<
  account extends Account | undefined = undefined,
> = EncryptedWalletActionsParameters & {
  gas: bigint;
  value?: bigint;
  accessList?: AccessList;
  nonce?: number;
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

export type DecryptionStatus = "pending" | "succeeded" | "failed";

export type EncryptedTransaction = Omit<
  Extract<Transaction, { type: "eip1559" }>,
  "type"
> & {
  type: "encrypted";
  typeHex: "0x8";
  epoch: bigint;
  encryptedFields: number;
  ciphertext: Hex;
  concealedFields: readonly EncryptedField[];
  decryptionStatus?: DecryptionStatus;
};

export type EncryptedTransactionReceipt = Omit<TransactionReceipt, "type"> & {
  type: "encrypted";
  decryptionStatus?: Exclude<DecryptionStatus, "pending">;
  failureReason?: string;
};
