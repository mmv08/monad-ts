# Phase 2: encrypted transactions for viem

**Status:** implemented internal reference, 24 September 2026. See [ENCRYPTED.md](./ENCRYPTED.md) for the delivered API and commands. The design below records the planning baseline.

**Branch:** `phase-2/viem-encrypted-transactions`, created from `btx` at `092e467`.

**Implementation choices:** the chain configuration export is `encryptedFormatters`, used with viem's existing `defineChain`; no `withEncryptedTransactions` helper was needed. The public action and decorator are `sendEncryptedTransaction` and `encryptedWalletActions`. Gas is required. Context injection remains one option. The codec stays in one module, and tests/mock/examples live outside sender code. Ordinary transactions use viem's formatters; chains with other custom response shapes must compose their own configuration explicitly. The finite reference transaction-size limit is 128 KiB. Managed nonce gaps after a failed local signing attempt require caller reconciliation; shared nonce state is not reset automatically.

**Validation review:** [ARCHITECTURE.md](./ARCHITECTURE.md) records the final validation boundaries. The sender now follows viem's trusted local-account convention, without parsing/recovering signer output. Signature serialization only encodes; mock/node admission enforces scalar ranges and low-s. Ordinary RPC fields use viem formatting, while ETX context/metadata retain their own checks. This supersedes the broader validation proposed below.

**Authority:** [parent delivery plan](../../../encrypted-transactions-plan.md), especially Phase 2 and section 7; [protocol PDF](../../../encrypted_txs_specs_wip.pdf), pp. 15–25 and 46–47. These files live beside the `monad-ts` checkout. Protocol changes must update the codec, fixtures, and this plan together.

## 1. Recommendation

Build in `packages/viem`, with the entry point **`@monad-crypto/viem/encrypted`**. Reuse `@monad-crypto/btx` for encryption and Ox for transaction encoding. Use viem's `.extend(...)` for actions and its chain formatters for transaction, block, and receipt responses.

The main operation should be **`wallet.sendEncryptedTransaction(...)`**. Its inputs should look like viem's `sendTransaction`: `to`, `value`, `data`, `accessList`, `gas`, fee caps, nonce, and an optional account override. It returns the usual transaction hash.

Do not make `sendTransaction({ type: "encrypted" })` the first API. A serializer controls bytes but does not make viem's preparation privacy-safe. Default preparation can fill, estimate, or simulate a transaction before the serializer runs. An explicit action gives us control of the whole sequence without changing ordinary viem actions. Keep `type: "encrypted"` as the internal envelope and formatted-response discriminator.

### Target developer experience

**Implementation rule:** reuse existing viem, Ox, and BTX code before adding a helper. Keep one public transaction action and one decorator. Export additional functions or options only when a concrete consumer flow proves they are needed. Internal test reuse does not justify a public export. Prefer direct functions and inferred types over service classes, generic adapter frameworks, or layers that only forward arguments.

Proposed API; these exports will be implemented during Phase 2:

```ts
import { createPublicClient, createWalletClient, http, parseEther } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { monad } from "viem/chains";
import {
  encryptedWalletActions,
  withEncryptedTransactions,
} from "@monad-crypto/viem/encrypted";

// The local mock will advertise this chain ID. It does not execute the EVM.
const chain = withEncryptedTransactions(monad);
const rpcUrl = "http://127.0.0.1:8545";
const account = privateKeyToAccount(generatePrivateKey());

const wallet = createWalletClient({
  account,
  chain,
  transport: http(rpcUrl, { retryCount: 0 }),
}).extend(encryptedWalletActions());

const publicClient = createPublicClient({
  chain,
  transport: http(rpcUrl, { retryCount: 0 }),
});

const hash = await wallet.sendEncryptedTransaction({
  to: "0x1111111111111111111111111111111111111111",
  value: parseEther("0.01"),
  gas: 21_000n,
});

const transaction = await publicClient.getTransaction({ hash });
if (transaction.type === "encrypted") {
  console.log(transaction.epoch, transaction.decryptionStatus);
}

// The mock's test control must advance the scripted outcome to resolve this.
const receipt = await publicClient.waitForTransactionReceipt({
  hash,
  checkReplacement: false,
  retryCount: 2,
});
if (receipt.type === "encrypted") {
  console.log(receipt.status, receipt.decryptionStatus);
}
```

The chain configuration must install ETX-aware response formatters; the inspected viem formatter does not recognize type 8. `withEncryptedTransactions` is the proposed single configuration export for that concrete need. Before adding it, check whether viem's existing `defineChain` configuration can express the same setup clearly with a formatter configuration export; ship only one form. Preserve chain ID, fees, and other chain settings. Configuration does not imply that the chain's public RPC accepts ETX. Examples always select a local mock endpoint.

Contract calls initially use existing viem ABI encoding:

```ts
import { encodeFunctionData, erc20Abi } from "viem";

await wallet.sendEncryptedTransaction({
  to: "0x2222222222222222222222222222222222222222",
  data: encodeFunctionData({
    abi: erc20Abi,
    functionName: "transfer",
    args: ["0x1111111111111111111111111111111111111111", 100n],
  }),
  gas: 100_000n,
});
```

ABI argument inference remains viem's. A separate `writeEncryptedContract` helper is unnecessary for the first delivery. Contract creation uses an explicit `to: null` plus `data` containing initcode; an omitted recipient is an error rather than accidental creation.

## 2. Technical stack and package boundary

| Layer | Choice | Responsibility |
| --- | --- | --- |
| Language | TypeScript, existing strict ESM/NodeNext setup | Typed requests, envelopes, RPC schemas, and lifecycle results; `.js` import suffixes |
| Client | viem `2.47.0` as the first tested baseline | Clients, transports, local accounts, fee reads, ABI encoding, response formatter hooks |
| Encryption | `@monad-crypto/btx: workspace:*` | Padding, BLS12-381 encryption, client proof, ciphertext serialization and admission |
| Transaction primitives | Direct, exact Ox dependency; start with `0.14.0`, used by viem `2.47.0` | `ox/Rlp`, `ox/Hex`, `ox/Bytes`, `ox/Hash`; no custom RLP implementation |
| Signing | viem local account and custom serializer | secp256k1 signature over the type-8 signing digest, with sender recovery checks |
| Runtime | Bun development; Node 20.19+ and modern browsers as consumers | Match BTX's supported runtime floor and secure platform randomness |
| Tests | `bun:test`, TypeScript compile-only fixtures | Offline codec, mock, type, privacy, and lifecycle checks |
| Mock | Shared TypeScript RPC handler, viem `custom(...)` transport | Actual signed bytes, admission, test decryption, scripted receipts |
| HTTP example | Thin `Bun.serve` wrapper over that handler | Loopback browser/manual testing, only when needed |
| Build/checks | Existing `tsc`, Bun workspaces, Biome | ESM and declarations, import isolation, reproducible local build |

Add explicit runtime dependencies on BTX and Ox; never rely on viem's transitive Ox installation. Keep noble dependencies inside BTX. Verify actual Ox exports against the pinned version before use; online docs can describe a newer version.

Add the `./encrypted` export pointing at `dist/encrypted/index.js` and its declarations. The root entry must not re-export or import it, so staking/WMON imports do not evaluate BTX. Put the mock outside `src` and the published build. Only test tooling imports `@monad-crypto/btx/testing`.

Delivery remains source-based and internal. The viem package currently publishes, while BTX is private. Before any merge to the release branch, explicitly keep this ETX-dependent build out of publication; skipping a Changeset alone is not a sufficient package-release design. Do not publish a viem version whose required BTX dependency is unavailable. Resolving public distribution belongs to later work.

The existing `viem >=2` peer range is broader than the versions checked here. Declare and test a justified minimum during implementation rather than claiming all v2 versions support the new entry point.

## 3. Public API and end-to-end types

### Actions

Expose `sendEncryptedTransaction(client, parameters)` and the same action through `encryptedWalletActions()`, following the repository's standalone/decorator convention. Both call one implementation. The existing root `monadActions()` stays the staking/WMON decorator.

| API | Result | Role |
| --- | --- | --- |
| `sendEncryptedTransaction` | viem `Hash` | Compose prepare, sign, and one raw submission |

Preparation, context lookup, codec operations, and signing are internal functions. There is no public prepared-transaction lifecycle, raw-submission wrapper, public-actions decorator, or custom receipt waiter in the initial API. Use the client's local account or an explicit local account override, following viem's account conventions.

Normal `getTransaction`, `getTransactionReceipt`, `getBlock`, and `waitForTransactionReceipt` work with the configured chain formatters. Standalone viem versions work too. Keep individual formatter functions internal; expose only the chain configuration needed to use them. Export the action's parameter/return/error types and necessary configuration/result types using existing viem naming conventions.

### Request types

Build a narrow request from viem's field types rather than accepting its whole transaction union:

- Required `to: Address | null`; `null` means creation and requires initcode.
- `value`, `data`, and `accessList` use viem types and default to `0n`, `"0x"`, and `[]`.
- `gas`, `maxFeePerGas`, `maxPriorityFeePerGas`, and value use `bigint`.
- Convenience chain ID and nonce follow viem's `number` convention, with safe-integer checks; the low-level codec uses `bigint` to cover full protocol u64 ranges without loss.
- `encryptedFields?: readonly [EncryptedField, ...EncryptedField[]]`, where `EncryptedField = "to" | "value" | "data" | "accessList"`. Omission means all four. Reject duplicates, unknown names, and empty selections at runtime. Map API `data` to protocol `input`.
- `paddedLength?: number` is an optional explicit override.
- Require `gas`. Callers who trust an estimator can use existing viem estimation tooling explicitly before calling this action and pass its result. This needs no new callback or estimation API.
- Reject `gasPrice`, blobs, sidecars, authorization lists, caller-provided ciphertext/epoch, and unrelated transaction types. Use `never` fields as well as runtime checks so wider input objects cannot silently enable them.

Preserve account and chain generics through the action and decorator. A client without a local account must supply one for signing; address-only/JSON-RPC accounts must fail type checks where statically known and fail clearly at runtime otherwise. Reuse viem's exported type utilities where they fit; add only the ETX constraints they cannot express.

### Context, prepared envelopes, and results

Use a discriminated context union:

```ts
type EncryptionContext =
  | { available: true; epoch: bigint; encryptionKey: Hex }
  | { available: false; epoch: bigint; encryptionKey: null };
```

Validate hex and integer ranges from `unknown` at the RPC boundary. A typed `client.request` describes the expected response but does not validate network data. BTX checks the key's canonical group encoding during encryption; the adapter checks RPC shape and the 576-byte width. Neither authenticates a malicious key source by itself.

Keep distinct types for plaintext requests, unsigned envelopes, signed envelopes, and query views. Keep construction local to the send operation and use owned hex values and copied nested access lists across asynchronous boundaries. Do not add a branded public prepared-transaction abstraction. Validate external inputs once at their boundary, then pass the validated values directly; avoid repeating checks between internal functions without a new trust boundary.

Returned transaction and receipt unions discriminate on `type: "encrypted"` and decryption status. Keep normal viem fields and units. `epoch` is `bigint`; mask is a validated `1..15` number. Mark pending concealed fields explicitly. A receipt's `status: "success" | "reverted"` and its decryption status are separate: successful decryption can still lead to an EVM failure.

Reuse viem's error conventions and existing errors where their meaning fits. Add ETX-specific errors only for distinct outcomes callers need to handle, with stable codes and preserved causes. Use `unknown` catches and ordinary narrowing through `instanceof` or discriminants; no separate error-helper API. TypeScript does not enforce checked exceptions. Avoid `any`, global augmentation of viem transaction types, and blanket `as unknown as` casts to make incompatible types compile.

**First implementation gate:** compile small consumer tests proving the serializer/account call, local-account inference, mixed transaction union narrowing, and nested block/receipt formatter inference with the installed viem version. Source inspection supports this design; those compile tests must establish the exact signatures before building the rest.

## 4. Codec and cryptographic construction

Keep this code pure and separate from actions. Use Ox's `Rlp.fromHex` to encode recursive hex lists and `Rlp.toHex` to decode them. Ox's `from`/`to` names are relative to hex, not RLP. Add ETX-specific shape, numeric, canonicality, and size validation around those primitives.

### Wire contract

Implement the EIP-2718/RLP convention below and record it beside byte fixtures:

```text
unsigned = 0x08 || RLP([
  chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas,
  to, value, input, accessList, epoch, encryptedFields, ciphertext
])

signed = 0x08 || RLP([the same 12 fields, yParity, r, s])
signingHash = keccak256(unsigned)
transactionHash = keccak256(signed)
```

The PDF fixes the type, order, widths, selected-field list, and binding but does not spell out every RLP/signature byte convention. Record the use of Ethereum typed-envelope RLP, the three signature suffix fields, and the same convention for the skeleton as explicit interpretations, with `TODO(spec)` where clarification remains. Fixtures make these choices reviewable; SDK/mock agreement alone does not prove node compatibility.

Numeric widths: chain ID, nonce, gas, and epoch are u64; fee caps u128; value u256; mask u8 with only bits 0–3. RLP integers use minimal big-endian bytes, with zero as the empty byte string. `to` is exactly 20 bytes for a call or empty for creation. Access-list entries contain a 20-byte address and 32-byte storage keys.

Reject noncanonical RLP, leading-zero integers, wrong list arity or nesting, trailing bytes, bad address/storage-key widths, integer overflow, invalid fee ordering, invalid signature parity/range/high-s, and incorrect placeholders. Do not assume a generic RLP decoder enforces all these rules. Bound total bytes and nesting before deep parsing or expensive curve work; check the final signed length, including RLP and signature overhead.

The PDF references chain size/gas limits without fixing all values. Keep those in an explicit backend/chain policy, separate from codec integer limits. Select and label finite local mock limits in the first milestone; do not call them production Monad limits. Padding must fit the chosen transaction limit and BTX's u32 masked-payload limit.

### Construction order

1. Validate and fill the full plaintext request and sender.
2. Choose the mask: `to=1`, `value=2`, `data=4`, `accessList=8`.
3. Build `M` as one RLP list containing only selected real values, in that order.
4. Replace selected outer values with the PDF placeholders: zero address, zero, empty bytes, and empty list. Hidden creation also uses the zero-address outer placeholder; its real empty `TxKind` stays in `M`.
5. Serialize the unsigned envelope with an empty ciphertext position to obtain the skeleton bytes. Hash them with Keccak-256.
6. Derive `AD = keccak256(0x01 || sender[20] || skeletonDigest[32])`. The preimage is exactly 53 bytes; no ABI encoding or extra length prefixes.
7. Call `encrypt({ plaintext, encryptionKey, associatedData, paddedLength? })` from BTX. Convert hex to owned bytes at this boundary.
8. Call `serializeCiphertext` and insert its bytes into the envelope.
9. Sign the complete unsigned type-8 envelope, then serialize its signature and compute the transaction hash.

BTX already supplies the desired default padding: a minimum of 256 bytes, rounded to a 256-byte multiple, excluding the four-byte encrypted length prefix. Do not add a second padding layer. Explicit exact-fit padding is valid; reject oversize or undersize requests without reducing them.

### Signing integration

Use `account.signTransaction(preparedEnvelope, { serializer })`. The serializer accepts the ordinary viem transaction union plus our ETX envelope, delegates ordinary variants to viem, and handles ETX with the pure codec. This matches viem's extension pattern and generic serializer constraint without falsely labelling ETX as EIP-1559.

Initial supported signers are viem private-key and HD secp256k1 accounts in Bun, Node, and the browser. Prove the custom-serializer path with compile and runtime fixtures. Parse the returned signed bytes and check that the unsigned fields and recovered sender match the prepared transaction before submission. A custom local account must honor the serializer contract; reject a signer that does not.

No message-signing prefix, EIP-712 substitute, plaintext transaction signature, or wrapper transaction enters this path. A fee bump, nonce change, field change, account change, or epoch change requires a new binding, encryption, and signature.

## 5. Preparation, RPC, and failure handling

### Privacy-safe preparation

Validate locally before network work. Resolve chain ID and verify it against the configured chain; use the pending nonce unless supplied. Reuse viem's chain, nonce, and fee actions, passing only public fields to any fee hook. Honor explicit values and validate them. Gas comes from the required input; callers can obtain it separately through trusted tooling.

Do not call general `prepareTransactionRequest`, `eth_fillTransaction`, `eth_call`, `eth_estimateGas`, `eth_simulateV1`, `debug_traceCall`, or `eth_createAccessList` on the default path. Do not auto-resolve a recipient name over RPC. Never fall back to a plaintext transaction.

Honor a viem account nonce manager when configured, with tests for allocation and failed preparation. Otherwise document the ordinary pending-nonce race between concurrent preparations and allow explicit nonces. Do not release an allocated nonce for reuse after an ambiguous send. Cross-process nonce coordination is the caller's responsibility.

Fetch a fresh encryption context after public-field resolution and just before encryption. Preparation finishes every public field before deriving AD. Use a copied snapshot so a caller cannot mutate a key buffer while work proceeds.

### Context provider

Default provider: typed `monad_getEncryptionContext` with no parameters, returning `{ epoch, encryptionKey, available }`. This is our internal mock/Anvil extension, not a method claimed to exist on the inspected BFT node.

Keep a narrow injected `contextProvider` option as required by the parent plan's context boundary, sharing the same option type between the standalone action and decorator. Both RPC and injected results pass through the same validator. Implement the mock RPC path first and test injection with a fixture; do not add provider factories, caching, or speculative contract adapters. Do not combine a key read with staking `getEpoch` or invent a DKG contract address.

RPC epoch/mask values use hex quantities. Accept numeric values only for the older adapter format and only when they are safe nonnegative integers within the relevant width. Unavailable context fails before encryption. A structurally valid but wrong key may pass proof admission and fail decryption; do not promise the proof authenticates the epoch key.

### Submission and retries

Submit exactly the signed bytes with `eth_sendRawTransaction`. Compute the hash locally first and verify that a successful RPC response returns that hash. A hash mismatch is an invalid response with an uncertain submission outcome, not a reason to send again.

Reuse viem's `sendRawTransaction`, which already uses `retryCount: 0`. Its fallback transport can still try a second endpoint independently of that option. Require a single-attempt transport on the wallet client and reject built-in fallback for this action; readers can use a separate ordinary public client. Do not add a submission-client option or transport wrapper. Document that arbitrary custom transports must honor the same single-attempt contract; an action cannot control hidden retries in user code.

For transient reads allow at most two retries after the first attempt, with bounded backoff. Keep the budget at one layer; avoid multiplying action retries by transport retries. Malformed data, unavailable keys, method-not-found, and other deterministic failures do not retry. Polling for inclusion is distinct from retrying a failed read.

Errors should distinguish invalid requests/contexts, encryption unavailable, expired epoch, unsupported signer, malformed envelopes/responses, explicit rejection, and unknown submission outcome. Preserve RPC `code`, `message`, and `data` and the original cause; normalize known `data.reason` values without inferring retry safety from the numeric code alone.

Timeout/disconnect after submission reports an unknown outcome and the local hash. Do not re-encrypt, re-sign, or resubmit. A later null lookup does not prove rejection. An active-epoch change requires explicit new preparation; acceptance can still race with rollover at admission or inclusion.

Errors and routine logs must not embed the plaintext request, estimation arguments, private keys, or randomness. Preserve the original submission RPC cause, but do not auto-log it; node-supplied messages remain untrusted text.

## 6. Queries and receipt semantics

Implement **three** chain formatters: transaction, transaction receipt, and block. In viem `2.47.0`, the default block formatter directly calls viem's built-in transaction formatter; setting only `formatters.transaction` does not format full ETX objects inside blocks. Map original nested RPC transactions explicitly through the ETX-aware formatter.

For ordinary transactions delegate to the original chain/viem formatter. For ETX normalize type `0x8` to `"encrypted"`, epoch, mask, ciphertext, concealed-field names, and lifecycle metadata. Preserve existing chain-specific formatter output and exact inferred return types.

| State | Transaction view | Receipt |
| --- | --- | --- |
| Pending | Original encrypted fields at placeholders; `encrypted: true`, `concealedFields`, `decryptionStatus: "pending"` | RPC returns null |
| Decrypted successfully | Restored execution fields, original hash/sender/signature/type; `decryptionStatus: "succeeded"` | Normal status/logs plus decryption status |
| Decryption/payload failure | All selected fields remain placeholders | Reverted, failed decryption status, typed reason, no logs or created contract |
| Late validation/EVM failure | Successfully restored fields | Reverted with decryption still successful and the appropriate execution reason |
| Rejected/dropped | No fabricated inclusion | No receipt |

Store original signed bytes separately from execution/query views. Never serialize restored fields to recover the original transaction hash. Use an explicit internal decryption result; valid zero/empty values do not mean failure. Validate response markers against the mask, and only expose restored data after the complete payload decodes.

For an older node response without lifecycle metadata, return an explicit unknown status or a typed unsupported-response error, according to the action's contract. Never invent success/failure from placeholders. Unknown backend reason strings retain their original value alongside a normalized `unknown` reason.

Use viem's existing `waitForTransactionReceipt({ hash, checkReplacement: false, retryCount: 2 })` with the ETX chain. It already supplies hash-specific polling, timeouts, intervals, and confirmations; the receipt formatter validates ETX metadata. Test these settings before considering any wrapper. Disabling replacement checks avoids classifying concealed intent from placeholders. A dropped transaction cannot be distinguished from an unknown hash through standard null responses alone.

## 7. Mock developed alongside the client

Build a deterministic in-process backend with one shared RPC dispatcher. Use `custom(...)` to attach it to ordinary viem clients. Add HTTP only for the browser/manual example, calling the same dispatcher and applying loopback binding, body-size limits, and explicit development CORS settings.

Implement only what these actions and tests need:

- Coherent key context, chain ID, pending nonce, balance/reserve fixtures, and fee/block reads used by the selected fee policy.
- Raw submission, lookup by hash/block/index, receipts, block number, and full/hash-only block responses.
- Test controls for key availability, rotation, pending expiry, scripted inclusion/outcomes, and transport faults. Controls are local test methods, not production RPC claims.
- Snapshot/reset helpers covering key context, stored bytes, pool, decryption outcomes, and scripted query state.

On submission, decode real bytes, enforce structural/size/public admission policy, recover sender, rebuild AD, and call `admitCiphertext(bytes, AD, { maxMaskedPayloadLength })`. Keep the canonical envelope/hash. At the scripted inclusion step, recheck the epoch and use `createTestKey().decrypt(bytes, AD, options)`; the testing API currently re-admits its wire input, so allow that bounded repeat instead of bypassing BTX's public boundary.

Decode the returned plaintext as the exact selected-field RLP list. Restore every field together or none. Distinguish proof/admission rejection from later wrong-key decryption failure, malformed plaintext, and scripted execution failure. Do not return test seeds/witnesses through public RPC.

The mock scripts the parent plan's outcomes: rejection/drop consumes no nonce or fee; included payload/late-validation failure consumes the nonce and charges the declared gas limit at the normal effective price in the fixture model. It executes no EVM call and cannot prove balances, deployment, or contract state changes. Label receipt outcomes as scripted in examples and test output. Anvil will test real state transitions in Phase 3.

## 8. Work sequence and acceptance gates

| Step | Deliverable | Gate |
| --- | --- | --- |
| 1. Type and wire contract | Consumer compile probes, minimal public types, documented RLP interpretation, dependency/export plan, finite local limits | Serializer signs actual ETX with a normal local account; no casts hiding type mismatches; mixed block/receipt types narrow correctly; every new export has a concrete use |
| 2. Pure codec and fixtures | Payload, mask/placeholders, envelope parser/serializer, skeleton, AD, signing/hash/recovery helpers | All 15 masks, creation, canonical rejection, and stored byte/hash fixtures pass |
| 3. Mock admission | In-process RPC, test key context, real raw-byte admission and decryption, explicit outcomes | Independently constructed malformed/rebound envelopes fail at the right stage; valid placeholder-valued payloads succeed |
| 4. Preparation and send | Internal preparation, coherent provider, required gas, viem nonce/fee/sign/send reuse, typed errors | Transfer and ABI-encoded call complete against the mock; recorded default RPC traffic contains no plaintext |
| 5. Query lifecycle | Chain formatters, existing viem receipt polling, rollover/drop and scripted receipt handling | Same original hash/sender across pending and restored views; full blocks and failure receipts have correct types and values |
| 6. Consumer delivery | Node and browser smoke examples, build instructions, updated architecture/docs, isolated offline test command | A fresh source checkout builds and runs the documented local flow without a live Monad RPC |

Steps 2 and 3 precede the convenience API. Write fixtures and rejection cases with each step; do not defer testing to the last milestone.

### Proposed layout

```text
packages/viem/
  src/encrypted/
    index.ts
    types.ts
    errors.ts
    decorator.ts
    chain.ts
    context.ts
    codec/
      payload.ts
      transaction.ts
      binding.ts
    actions/
      sendEncryptedTransaction.ts
    formatters/
      transaction.ts
      transactionReceipt.ts
      block.ts
  test/encrypted/
    mock/
    fixtures/
    types/
    *.test.ts
  examples/encrypted/
  PHASE-2-PLAN.md
```

Keep modules small when separate rules warrant it; this is a boundary map, not a required file count. Extract internal functions when they clarify a protocol step or remove actual duplication, not to anticipate future callers. Keep one implementation for each rule and use viem/Ox/BTX for rules they already implement. Update `ARCHITECTURE.md`, README, action/decorator JSDoc, and repository guidance for the new signing, dependency, and validation boundaries. Decorator JSDoc must match its action implementation.

### Required tests

1. **Codec and binding:** all 15 nonempty masks; empty/zero legitimate fields; hidden and public creation; u64/u128/u256 boundaries; malformed RLP/access lists; high-s signatures; changed sender, chain, nonce, fees, gas, epoch, mask, and exposed fields; no partial restoration.
2. **Fixtures:** store plaintext field values, mask, payload bytes, skeleton bytes/digest, AD, ciphertext, unsigned/signed bytes, signing hash, recovered sender, and transaction hash. Deterministic randomness stays in test-only BTX fixture tooling, never in the sender API. Include hand-reviewed construction cases and clearly label self-generated vectors as regression evidence.
3. **Privacy:** record every request and spy on plaintext-sensitive methods; preparation must not call them. Test passing gas obtained separately from an explicitly trusted estimator. Check error formatting, no access-list generation, no plaintext fallback, and no key/context fabrication.
4. **RPC/lifecycle:** unavailable context, malformed/unsafe numeric context, wrong key, rollover before admission and inclusion, explicit rejection, null lookup, pending-to-scripted outcomes, invalid returned hash, dropped transaction, and ambiguous timeout after backend acceptance. Count underlying sends, including fallback transport tests.
5. **Type tests:** missing/JSON-RPC signer, missing gas, bad field names/empty tuple, forbidden transaction fields, wrong ABI arguments, envelope/query-view misuse, safe account overrides, standalone/decorator parity, and transaction/receipt/block inference. Use `@ts-expect-error` negative cases and positive type-equality checks. Verify the package exports only the agreed public surface.
6. **Consumer/build:** import compiled ESM and declarations from the package export in Bun and Node; run a browser encryption/signing smoke flow using a local bundled page and test backend. Check dependency graphs to keep testing/trapdoor code out of sender bundles and BTX out of root read-only imports.

Provide `test:encrypted` for offline runs; the existing viem suites use live RPC and must not be prerequisites for mock testing. Keep existing coverage policy. Build BTX before the viem package, run package type checks and Biome, then focused offline coverage and consumer checks. Suggested commands once scripts exist:

```bash
bun install
bun run --cwd packages/btx build
bun run --cwd packages/viem build
bun run --cwd packages/viem typecheck
bun run --cwd packages/viem test:encrypted
bun run lint
```

## 9. Phase 2 completion

Done means a developer can build from Git, configure an ordinary viem local account and transport, call `sendEncryptedTransaction` for a transfer or ABI-encoded call, and inspect correctly typed transactions and scripted receipts. The backend receives actual signed type-8 bytes, verifies their binding, and decrypts the payload using the separate BTX test API. Expected failures run offline and preserve transaction identity and privacy-safe defaults.

Phase 3 reuses the RPC contract, fixtures, examples, and client tests against ETX-enabled Anvil, adding EVM state assertions. A real node comparison then supplies independent interoperability evidence.

## 10. Source checks behind this design

- [Viem custom clients and `.extend`](https://viem.sh/docs/clients/custom).
- Installed viem `2.47.0`: `accounts/types.ts`, `accounts/utils/signTransaction.ts`, and `zksync/serializers.ts` establish custom local-account serialization and the ordinary/custom transaction union pattern.
- Installed viem: `actions/wallet/sendRawTransaction.ts` disables action retries; `clients/transports/fallback.ts` still advances endpoints on eligible errors.
- Installed viem: `utils/formatters/transaction.ts`, `transactionReceipt.ts`, and `block.ts` establish where ETX normalization must occur.
- Installed viem: `actions/public/waitForTransactionReceipt.ts` compares `to`, `value`, and `input` to classify replacements, which cannot establish ETX intent.
- [Ox RLP encoding](https://oxlib.sh/api/Rlp/fromHex) and [decoding](https://oxlib.sh/api/Rlp/toHex).
- BTX's current `README.md`, `src/index.ts`, and `package.json` establish its byte API, padding, test-only decryptor boundary, dependencies, and Node runtime floor.

These are design/source checks, not results from an implemented adapter or a running ETX node.
