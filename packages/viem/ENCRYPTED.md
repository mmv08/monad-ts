# Encrypted transactions

Internal reference implementation, built from this checkout. Requires viem 2.56.8+ (v2), Bun or Node 20.19+, or a modern browser with secure randomness. This build is private because it depends on the private BTX workspace package.

## Build and run

From the `monad-ts` root:

```sh
bun install
bun run --cwd packages/btx build
bun run --cwd packages/viem typecheck
bun run --cwd packages/viem test:encrypted
bun run packages/viem/examples/encrypted.ts
```

`test` and `test:encrypted` build the package first, because one test runs the compiled output under Node. The example sends a transfer and an ABI-encoded contract call to the in-process mock. The mock verifies and decrypts the signed bytes, then returns scripted receipts. It does not execute the EVM or provide threshold privacy.

For browser signing over HTTP:

```sh
bun run packages/viem/examples/encrypted-server.ts
```

Open `http://127.0.0.1:8545`. The server holds the test trapdoor; the browser generates its own local signing account. The server wraps the same mock, accepts same-origin requests only, and limits the body size.

## API

```ts
import { createPublicClient, createWalletClient, defineChain, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { monad } from "viem/chains";
import {
  encryptedFormatters,
  encryptedWalletActions,
} from "@monad-crypto/viem/encrypted";

// Match this ID to your local backend; the browser example uses 1337.
const chain = defineChain({
  ...monad,
  id: 1337,
  formatters: encryptedFormatters,
  supportsTransactionReplacementDetection: false,
});
const transport = http("http://127.0.0.1:8545/rpc");
const account = privateKeyToAccount(`0x${"01".repeat(32)}`); // Test key only.
const wallet = createWalletClient({ account, chain, transport })
  .extend(encryptedWalletActions());
const client = createPublicClient({ chain, transport });

const hash = await wallet.sendEncryptedTransaction({
  to: "0x1111111111111111111111111111111111111111",
  value: 1n,
  gas: 21_000n,
});
const receipt = await client.waitForTransactionReceipt({ hash });
if (receipt.type === "encrypted") {
  console.log(receipt.decryptionStatus);
}
```

`sendEncryptedTransaction(client, parameters)` is the standalone form of the same action. Use viem's `encodeFunctionData` for contract calls.

- `to` and `gas` are required. Use `to: null` with `data` for contract creation; an omitted `to` is an error.
- `value`, `data`, and `accessList` default to zero, empty bytes, and an empty list.
- All four fields are encrypted by default. `encryptedFields: ["to", "data"]` picks a nonempty subset. A public access list can reveal the target.
- `paddedLength` overrides BTX's default padding, which rounds up to a multiple of 256 bytes, with 256 as the minimum. It excludes the four-byte length prefix, and an exact fit is allowed.
- The nonce and fee caps may be supplied. Otherwise the action fills them as viem's `prepareTransactionRequest` does for local accounts: fee hooks get the latest block, and the request they see carries public fields only. The chain ID comes from the client's chain, or from the node when the client has none. Unlike viem, the action runs no chain `prepareTransactionRequest` hooks, which would see the plaintext, and ignores `client.dataSuffix`.
- The action never estimates gas. Estimate on a node you trust with the plaintext, then pass `gas`.
- Local private-key and HD accounts work, including viem nonce managers. JSON-RPC wallets do not. As in viem, the action trusts what a local account signs.
- The formatters handle ordinary transactions and ETX. A chain with its own response formatters must combine them with these by hand.

## Context and errors

By default the action reads the **internal** `monad_getEncryptionContext` RPC. It takes no arguments and returns `{ epoch, encryptionKey, available }`. It is our mock's extension, later Anvil's; the inspected Monad node code has no such method.

Pass `contextProvider: async ({ chainId, account }) => context` to the action, or to `encryptedWalletActions` as a default, for fixtures or another key source. It must return one coherent snapshot, and the caller must trust its source. When encryption is unavailable, the action fails before encrypting.

Validation stays where viem and BTX already do it. `assertRequest` checks addresses and fee caps before any RPC call; it is the only check on an encrypted `to`, because the serializer sees the placeholder. The type-8 serializer makes the checks of viem's EIP-1559 serializer: `assertTransactionEIP1559` for the chain ID, recipient and fee caps, `numberToHex` for integers, and `serializeAccessList` for the access list. Like viem for EIP-1559, it leaves the PDF's integer widths to the node. BTX checks the key and padding. Their errors reach the caller unchanged. The formatters convert ETX fields without validating them, as viem's formatters do.

`EncryptedTransactionError` covers the cases viem has no error for. Inspect `code`:

- `invalidInput`: `to` is missing, or `encryptedFields` is empty or names an unknown field.
- `unsupportedSigner`: the account is missing or not local.
- `unavailable`: the context has no key for the active epoch.
- `rejected`: the backend's error carried a structured `data.reason`, such as `expiredEpoch`. `error.walk()` reaches it.
- `unknownOutcome`: the send failed or was aborted without a reason. The transaction may still be pending, so look up `hash` before acting.

On success the action returns the hash of the signed bytes; it does not compare it with the node's reply. Submission failures carry that `hash`, and the original error as `cause`. The action sends once and never re-encrypts or signs again; viem's `sendRawTransaction` already disables retries, and reads follow the transport's own retry setting. As in viem, any failure after the action takes a managed nonce resets the nonce manager, so the next send reads the pending nonce from the node. A null lookup does not prove that the node rejected a transaction.

## Identity and limits

Transactions use type `0x08`, the PDF's four-field mask, the version-1 sender/skeleton binding, BTX encryption, and a secp256k1 signature over the full typed envelope. The codec uses Ethereum-style typed RLP with a `yParity, r, s` suffix. The PDF does not spell out every RLP convention, so the committed vector records this reading for later comparison with a node.

Pending queries show placeholders and name the concealed fields. After decryption, queries show the restored fields but keep the original hash, sender and signature. Lifecycle metadata the node omits stays undefined, and a valid zero or empty value never implies failure.

A receipt's decryption status and execution status are separate. Set `supportsTransactionReplacementDetection: false` on the ETX chain: concealed fields cannot show whether another transaction replaced the same intent. That turns off replacement checks for every wait on the chain; pass `checkReplacement: false` to each ETX wait instead if ordinary waits should keep them.

`test/encrypted/mock.ts` holds all decoding and admission code; the sender build has none. The mock gives every rejection a structured reason. It admits a ciphertext made under the wrong key, because the proof binds the transaction rather than the key, then fails its decryption without restoring any field.

The regression vector is self-generated, not independent evidence of compatibility. Regenerate it after an intentional wire change:

```sh
bun run packages/viem/test/encrypted/fixtures.ts
```

Anvil EVM execution and comparison with a compatible node come in later phases.
