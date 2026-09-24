import {
  encryptedWalletActions,
  sendEncryptedTransaction,
} from "@monad-crypto/viem/encrypted";
import {
  createPublicClient,
  createWalletClient,
  custom,
  type Hash,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { chain } from "./mock.js";

// Compile-only consumer checks. This function is never invoked.
export async function checkTypes() {
  const transport = custom({ request: async () => null });
  const account = privateKeyToAccount(`0x${"01".repeat(32)}`);
  const wallet = createWalletClient({ account, chain, transport }).extend(
    encryptedWalletActions(),
  );
  const unbound = createWalletClient({ chain, transport }).extend(
    encryptedWalletActions(),
  );
  const to = "0x1111111111111111111111111111111111111111";
  const hash: Hash = await wallet.sendEncryptedTransaction({
    to,
    gas: 21_000n,
  });
  await sendEncryptedTransaction(wallet, { to, gas: 21_000n });
  await unbound.sendEncryptedTransaction({ account, to, gas: 21_000n });
  // @ts-expect-error gas is required
  await wallet.sendEncryptedTransaction({ to });
  // @ts-expect-error explicit local account required
  await unbound.sendEncryptedTransaction({ to, gas: 21_000n });
  // @ts-expect-error JSON-RPC address is not a local signer
  await wallet.sendEncryptedTransaction({ account: to, to, gas: 21_000n });
  // @ts-expect-error creation requires initcode
  await wallet.sendEncryptedTransaction({ to: null, gas: 21_000n });
  // @ts-expect-error unsupported blob fields
  await wallet.sendEncryptedTransaction({ to, gas: 21_000n, blobs: [] });
  await wallet.sendEncryptedTransaction({
    to,
    gas: 21_000n,
    // @ts-expect-error empty mask is invalid
    encryptedFields: [],
  });
  await wallet.sendEncryptedTransaction({
    to,
    gas: 21_000n,
    // @ts-expect-error unknown field
    encryptedFields: ["nonce"],
  });
  const publicClient = createPublicClient({ chain, transport });
  const transaction = await publicClient.getTransaction({ hash });
  if (transaction.type === "encrypted") {
    const epoch: bigint = transaction.epoch;
    void epoch;
  }
  const block = await publicClient.getBlock({ includeTransactions: true });
  for (const transaction of block.transactions)
    if (transaction.type === "encrypted") {
      const epoch: bigint = transaction.epoch;
      void epoch;
    }
  const receipt = await publicClient.waitForTransactionReceipt({
    hash,
  });
  if (receipt.type === "encrypted" && receipt.decryptionStatus === "failed") {
    const reason: string = receipt.failureReason;
    void reason;
  }
}
