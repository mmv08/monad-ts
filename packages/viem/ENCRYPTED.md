# Encrypted transactions

Internal reference implementation, built from this checkout. Requires viem 2.47+ (v2), Bun or Node 20.19+, or a modern browser with secure randomness. This build is private because it depends on the private BTX workspace package.

## Build and run

From the `monad-ts` root:

```sh
bun install
bun run --cwd packages/btx build
bun run --cwd packages/viem build
bun run --cwd packages/viem typecheck
bun run --cwd packages/viem test:encrypted
bun run packages/viem/examples/encrypted.ts
```

The example sends a transfer and an ABI-encoded contract call to the in-process mock. It verifies and decrypts actual signed bytes, then returns scripted receipts. It does not execute the EVM or provide threshold privacy.

For browser signing over HTTP:

```sh
bun run packages/viem/examples/encrypted-server.ts
```

Open `http://127.0.0.1:8545`. The server holds the test trapdoor; the browser generates its own local signing account. This server exposes the same mock dispatcher, with same-origin requests and a body-size limit.

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
const chain = defineChain({ ...monad, id: 1337, formatters: encryptedFormatters });
const transport = http("http://127.0.0.1:8545/rpc", { retryCount: 0 });
const account = privateKeyToAccount(`0x${"01".repeat(32)}`); // Test key only.
const wallet = createWalletClient({ account, chain, transport })
  .extend(encryptedWalletActions());
const client = createPublicClient({ chain, transport });

const hash = await wallet.sendEncryptedTransaction({
  to: "0x1111111111111111111111111111111111111111",
  value: 1n,
  gas: 21_000n,
});
const receipt = await client.waitForTransactionReceipt({
  hash,
  checkReplacement: false,
  retryCount: 2,
});
if (receipt.type === "encrypted") {
  console.log(receipt.decryptionStatus);
}
```

The standalone `sendEncryptedTransaction(client, parameters, options?)` calls the same implementation. There are no public preparation, signing, raw-send, or receipt-waiting wrappers. Use viem's `encodeFunctionData` for contract calls.

- `to` and `gas` are required. Use `to: null` and `data` for creation. A missing recipient is an error.
- `value`, `data`, and `accessList` default to zero, empty bytes, and an empty list.
- All four fields are concealed by default. `encryptedFields: ["to", "data"]` selects a nonempty subset. Exposing an access list can reveal the target.
- `paddedLength` overrides BTX's 256-byte rounding. It excludes the four-byte encrypted length prefix. Exact-fit padding is allowed.
- Nonce, chain ID, and fee caps can be supplied; otherwise the action uses viem public reads. Nonce and chain ID must fit JavaScript safe integers; the internal wire codec supports full u64 values.
- Gas estimation is never automatic. Estimate separately only on a node you trust with the plaintext, then pass `gas`.
- Local private-key/HD accounts work, including viem nonce managers. JSON-RPC wallets are unsupported. A custom local signer must honor viem's serializer contract.
- The formatters support ordinary Ethereum transactions and ETX. On a chain with custom response formatters, explicitly compose its custom behavior; do not silently overwrite it.

## Context and errors

The default context source is the **internal** `monad_getEncryptionContext` RPC, with no arguments, returning `{ epoch, encryptionKey, available }`. This is not a claim that a public Monad node exposes that method. The key is 576 bytes and belongs to the stated active epoch.

Both the decorator and standalone action accept `contextProvider: async ({ chainId, account }) => context` for fixtures or a supplied key source. It must return one coherent snapshot; source authentication remains the caller's responsibility. An unavailable key fails before encryption.

Catch `EncryptedTransactionError` and inspect `code`. On `unknownOutcome`, `hash` identifies the attempted send. The original submission error remains in `cause`. The action does not retry submission, re-encrypt, or sign again. Unknown rejection reasons remain uncertain rather than proving rejection. A null lookup does not prove the node rejected a transaction.

Use a single-attempt wallet transport. Built-in fallback is rejected because it can submit to another endpoint after a timeout. Custom transports must honor the same rule. Internal public reads allow two retries through viem's request machinery; deterministic local validation does not retry.

Viem nonce managers reserve a nonce before encryption/signing. A later local failure can leave a gap; use an explicit nonce after checking pending state. The action never resets shared nonce-manager state or releases a nonce after an uncertain send. Without a nonce manager, concurrent calls have viem's ordinary pending-nonce race.

## Identity and limits

Transactions use type `0x08`, the PDF's four-field mask, version-1 sender/skeleton binding, BTX encryption, and a secp256k1 signature over the full typed envelope. The codec uses Ethereum-style typed RLP and the `yParity, r, s` suffix. The PDF does not spell out every RLP convention; fixtures record this interpretation for later node comparison.

The reference total-size limit is 128 KiB, including the signature. This is a finite local policy, not a production Monad limit. No ETX surcharge is added.

Pending queries show placeholders and concealed-field markers. Decrypted queries show an execution view while keeping the original hash, sender, and signature. Never serialize restored fields to compute the signed transaction hash. Missing lifecycle metadata yields `unknown`; valid zero/empty values never imply failure.

Receipt decryption status and execution status are separate. Disable viem's replacement classification when waiting: concealed fields cannot establish whether another transaction changed the same intent. The mock drops expired pending transactions without a receipt; included failures use scripted full-gas-limit charges and nonce consumption.

The regression vector is self-generated, not independent compatibility evidence. Regenerate it after an intentional wire change:

```sh
bun run packages/viem/test/encrypted/fixtures.ts
```

Anvil EVM execution and comparison with a compatible node remain later phases.

## Verification recorded for this change

- Workspace build and type checks passed.
- 39 offline ETX tests passed, including compiled package imports and Node signing.
- The browser HTTP example encrypted and signed locally in headless Chrome and received a scripted success receipt.
- Focused Biome checks passed. The root lint command encountered existing nested Biome configurations in `.claude/worktrees/`.
- Coverage was measured without changing the repository's thresholds. Sender source functions reached 100%; formatter source lines reached 98.29% (the remaining guard checks viem's own formatter discriminator). The combined report also includes partially exercised BTX source/build files and compiled consumer modules, so its aggregate is not a sender-only coverage figure.
