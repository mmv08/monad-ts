# @monad-crypto/btx

Encrypt byte payloads for Monad encrypted transactions. Includes padding, client proofs, and ciphertext encoding. Transaction construction and RPC are outside this package.

> Internal, unaudited reference implementation. Not for production use.

## Setup

From the `monad-ts` root:

```bash
bun install
bun run --cwd packages/btx build
```

Other workspace packages can add `"@monad-crypto/btx": "workspace:*"` to their dependencies. For Node.js, use 20.19 or newer.

## Example

Save as `packages/btx/example.ts` and run `bun run packages/btx/example.ts` from the repo root.

This uses a test key, not validator shares. Anyone with the test key can decrypt its ciphertexts.

```ts
import {
  encrypt,
  serializeCiphertext,
} from "@monad-crypto/btx";
import { createTestKey } from "@monad-crypto/btx/testing";

const key = createTestKey();
const encoder = new TextEncoder();
const plaintext = encoder.encode("hello");
const associatedData = encoder.encode("example context");
const ciphertext = encrypt({
  plaintext,
  encryptionKey: key.encryptionKey,
  associatedData,
});
const result = key.decrypt(serializeCiphertext(ciphertext), associatedData);
if (result === null) throw new Error("Decryption failed");
console.log(new TextDecoder().decode(result.plaintext)); // hello
```

For transactions, supply the 576-byte epoch encryption key in CatBLST's canonical order and construct the associated data that binds the ciphertext to the transaction. Both inputs are `Uint8Array` values. Encryption rejects non-canonical keys, keys outside G_T, and the identity. The caller must still authenticate the key's source and epoch.

## API

| Call | Result |
| --- | --- |
| `encrypt` | A `Ciphertext` object |
| `admitCiphertext(bytes, associatedData, options?)` | Decodes and verifies received wire bytes once, returning a `Ciphertext` with owned bytes. Options can set `maxMaskedPayloadLength`. |
| `serializeCiphertext` | Encodes an object as wire bytes, checking component widths. Does not check the proof. |
| `verifyDecryption` | Checks a plaintext and recovered seed against the commitment, masked seed, and masked payload under the encryption key. Returns `true` or `false`. |
| `key.decrypt(bytes, associatedData, options?)` | Admits and decrypts wire bytes once, returning `{ plaintext, seed }` or `null` if padding or plaintext checks fail. Accepts the same size-limit option as admission. |

Pass the unchanged result of `admitCiphertext` to `verifyDecryption({ ciphertext, encryptionKey, plaintext, seed, associatedData })`: the latter does not check the proof. Supply the same authenticated epoch key used for encryption. An invalid key throws; a valid but wrong key returns `false`.

Admitted ciphertexts own their bytes but remain mutable. Admission proves validity at that call, not after later edits. The test decryptor accepts wire bytes directly; use `serializeCiphertext` for objects returned by encryption. Encryption, decryption, and witness verification leave caller inputs unchanged.

Protocol rejections throw `BtxError`; use its `code` to distinguish them. Invalid types or byte lengths can throw `TypeError` or `RangeError`, including in `verifyDecryption`.

Wire size limits run before payload copying and curve work. Test keys require a positive u32 `maxBatchSize` and a trapdoor in `[1, q)`; invalid values throw `RangeError`.

Encryption always uses secure platform randomness. Fixtures supply deterministic randomness through an internal helper, outside the package API.

## Padding

By default, `encrypt` rounds the plaintext length up to a multiple of 256 bytes, with a minimum of 256. `paddedLengthFor(length)` returns that size. Set `paddedLength` to override it; use the plaintext length to add no zero filler.

`paddedLengthFor` rejects negative, fractional, or non-finite inputs and lengths whose padded result would exceed the ciphertext's u32 length limit.

| Size | Meaning |
| --- | --- |
| `paddedLength` | Plaintext capacity, excluding its four-byte length prefix |
| `maskedPayload.length` | `4 + paddedLength`; this is what `maxMaskedPayloadLength` limits when decoding |
| Wire length | `CIPHERTEXT_OVERHEAD + maskedPayload.length`, or `136 + paddedLength` |

For example, a padded length of 256 gives 260 masked-payload bytes and 392 wire bytes. Decoding has no size limit unless the caller sets `maxMaskedPayloadLength`. A supplied limit must be a nonnegative safe integer; omit it rather than passing `Infinity`.

## Imports

- `@monad-crypto/btx`: encryption, ciphertext encoding, and verification.
- `@monad-crypto/btx/testing`: test keys and decryption. Keep this out of sender code.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for source layout, test commands, and specification details.

License: MIT.
