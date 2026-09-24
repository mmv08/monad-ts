import { bytesToHex, hexToBytes, keccak256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";
// All of BTX comes from one copy, its source. Deterministic randomness belongs
// only to fixture tooling, never the package entry point.
import { encryptWithRandom } from "../../../btx/src/btx.js";
import { serializeCiphertext } from "../../../btx/src/index.js";
import { createTestKey } from "../../../btx/src/testing.js";
import {
  associatedData,
  conceal,
  type Envelope,
  encodePayload,
  serializeEnvelope,
  serializeTransaction,
} from "../../src/encrypted/codec.js";

export async function buildVector() {
  const account = privateKeyToAccount(`0x${"01".repeat(32)}`);
  const key = createTestKey({ trapdoor: 42n });
  const payload = {
    to: null,
    value: 0n,
    data: "0x60006000" as const,
    accessList: [],
  };
  const envelope: Envelope = {
    type: "encrypted",
    chainId: 1337,
    nonce: 7,
    gas: 100_000n,
    maxFeePerGas: 3n,
    maxPriorityFeePerGas: 1n,
    epoch: 1n,
    encryptedFields: 15,
    ciphertext: "0x",
    ...conceal(payload, 15),
  };
  const plaintext = encodePayload(payload, 15);
  const skeleton = serializeEnvelope(envelope);
  const ad = associatedData(envelope, account.address);
  const seed = Uint8Array.from({ length: 16 }, (_, index) => index);
  envelope.ciphertext = bytesToHex(
    serializeCiphertext(
      encryptWithRandom(
        {
          plaintext: hexToBytes(plaintext),
          encryptionKey: key.encryptionKey,
          associatedData: hexToBytes(ad),
          paddedLength: 256,
        },
        () => seed.slice(),
        () => 123n,
      ),
    ),
  );
  const unsigned = serializeEnvelope(envelope);
  const signed = await account.signTransaction(envelope, {
    serializer: serializeTransaction,
  });
  return {
    version: 1,
    description:
      "Self-generated regression vector; typed RLP interpretation, not independent node conformance",
    trapdoor: "42",
    seed: bytesToHex(seed),
    proofNonce: "123",
    sender: account.address,
    plaintext,
    skeleton,
    skeletonDigest: keccak256(skeleton),
    associatedData: ad,
    ciphertext: envelope.ciphertext,
    unsigned,
    signingHash: keccak256(unsigned),
    signed,
    transactionHash: keccak256(signed),
  };
}

if (import.meta.main) {
  await Bun.write(
    new URL("./vector.json", import.meta.url),
    `${JSON.stringify(await buildVector(), null, 2)}\n`,
  );
}
