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
  deserializeCiphertext,
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
const received = deserializeCiphertext(serializeCiphertext(ciphertext));
const result = key.decrypt(received, associatedData);
if (result === null) throw new Error("Decryption failed");
console.log(new TextDecoder().decode(result.plaintext)); // hello
```

For transactions, supply the 576-byte epoch encryption key in CatBLST's canonical order and construct the associated data that binds the ciphertext to the transaction. Both inputs are `Uint8Array` values. Encryption rejects non-canonical keys, keys outside G_T, and the identity. The caller must still authenticate the key's source and epoch.

## API

| Call | Result |
| --- | --- |
| `encrypt` | A `Ciphertext` object |
| `serializeCiphertext` / `deserializeCiphertext` | Convert between the object and wire bytes. Decoding checks the encoding, not the proof. |
| `assertValidCiphertext` | Checks the commitment and proof. Returns nothing on success; throws on rejection. |
| `verifyDecryption` | Checks a plaintext and recovered seed against the commitment, masked seed, and masked payload under the encryption key. Returns `true` or `false`. |
| `key.decrypt` | Checks the ciphertext, then returns `{ plaintext, seed }`, or `null` if padding or plaintext checks fail. Throws if the commitment or proof fails. |

Run `assertValidCiphertext(ciphertext, associatedData)` before `verifyDecryption({ ciphertext, encryptionKey, plaintext, seed, associatedData })`: the latter does not check the proof. Supply the same authenticated epoch key used for encryption. An invalid key throws; a valid but wrong key returns `false`.

Protocol rejections throw `BtxError`; use its `code` to distinguish them. Invalid types or byte lengths can throw `TypeError` or `RangeError`, including in `verifyDecryption`.

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
