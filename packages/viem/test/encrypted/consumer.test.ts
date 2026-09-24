import { expect, test } from "bun:test";
import { createWalletClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { chain, createMock } from "./mock.js";

test("compiled export surface and real signing under Node", async () => {
  const api = await import("@monad-crypto/viem/encrypted");
  expect(Object.keys(api).sort()).toEqual([
    "EncryptedTransactionError",
    "encryptedFormatters",
    "encryptedWalletActions",
    "sendEncryptedTransaction",
  ]);
  const mock = createMock();
  const wallet = createWalletClient({
    chain,
    transport: mock.transport,
    account: privateKeyToAccount(`0x${"01".repeat(32)}`),
  });
  expect(
    await api.sendEncryptedTransaction(wallet, {
      to: "0x1111111111111111111111111111111111111111",
      gas: 21_000n,
    }),
  ).toMatch(/^0x[\da-f]{64}$/);
  const node = Bun.spawn(
    [
      "node",
      "--input-type=module",
      "-e",
      `
    import { sendEncryptedTransaction } from '@monad-crypto/viem/encrypted';
    import { createTestKey } from '@monad-crypto/btx/testing';
    import { createWalletClient, custom, bytesToHex, keccak256 } from 'viem';
    import { privateKeyToAccount } from 'viem/accounts';
    const key = createTestKey({trapdoor: 42n});
    let sent;
    const client = createWalletClient({account: privateKeyToAccount('0x' + '01'.repeat(32)), transport: custom({request: async ({method, params}) => {
      if (method === 'eth_chainId') return '0x539';
      if (method === 'eth_sendRawTransaction') { sent = params[0]; return keccak256(sent); }
      throw Error('Unexpected RPC');
    }}, {retryCount: 0})});
    const hash = await sendEncryptedTransaction(client, {to: '0x' + '11'.repeat(20), gas: 21000n, nonce: 0, maxFeePerGas: 3n, maxPriorityFeePerGas: 1n}, {contextProvider: async () => ({epoch: 1n, available: true, encryptionKey: bytesToHex(key.encryptionKey)})});
    if (!sent.startsWith('0x08') || hash !== keccak256(sent)) throw Error('Invalid signed envelope');
    console.log('Node signed type 8');
  `,
    ],
    {
      cwd: new URL("../../", import.meta.url).pathname,
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  const [stdout, stderr, exit] = await Promise.all([
    new Response(node.stdout).text(),
    new Response(node.stderr).text(),
    node.exited,
  ]);
  expect(stderr).toBe("");
  expect(exit).toBe(0);
  expect(stdout).toContain("Node signed type 8");
});

test("browser bundles isolate testing code and root read actions", async () => {
  for (const [entrypoint, forbidden] of [
    ["../../src/encrypted/index.ts", ["createTestKey", "trapdoor"]],
    ["../../src/index.ts", ["btx/nizk", "encryptWithRandom", "trapdoor"]],
  ] as const) {
    const result = await Bun.build({
      entrypoints: [new URL(entrypoint, import.meta.url).pathname],
      target: "browser",
    });
    expect(result.success).toBe(true);
    for (const output of result.outputs) {
      const source = await output.text();
      for (const term of forbidden) expect(source).not.toContain(term);
    }
  }
});
