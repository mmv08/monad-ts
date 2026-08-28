import { expect, test } from "bun:test";
import { createServer } from "node:net";

import {
  createPageTrie,
  type PageTrieBatchOperation,
  SLOT_SIZE,
} from "../src/index.js";

const ANVIL_BIN = process.env.ANVIL_BIN ?? "anvil";
const MINIMUM_ANVIL_VERSION = [1, 8, 0] as const;
// The constructor returns `PUSH1 0x20; CALLDATALOAD; PUSH0; CALLDATALOAD;
// SSTORE; STOP`, writing calldata[32:64] to the slot in calldata[0:32].
const STORAGE_CONTRACT_INIT_CODE = "0x6007600a5f3960075ff36020355f355500";

type JsonRpcResponse<T> =
  | { jsonrpc: "2.0"; id: number; result: T }
  | {
      jsonrpc: "2.0";
      id: number;
      error: { code: number; message: string };
    };

type TransactionReceipt = {
  contractAddress: string | null;
  status: string;
};

let requestId = 0;

function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")}`;
}

function hexToWord(hex: string): Uint8Array {
  const value = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (
    value.length > SLOT_SIZE * 2 ||
    value.length % 2 !== 0 ||
    !/^[0-9a-fA-F]*$/.test(value)
  ) {
    throw new RangeError(`invalid storage word: ${hex}`);
  }

  const padded = value.padStart(SLOT_SIZE * 2, "0");
  return Uint8Array.from({ length: SLOT_SIZE }, (_, index) =>
    Number.parseInt(padded.slice(index * 2, index * 2 + 2), 16),
  );
}

function uint256(value: bigint): Uint8Array {
  const bytes = new Uint8Array(SLOT_SIZE);
  for (let i = bytes.length - 1; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

function toQuantity(value: bigint): `0x${string}` {
  return `0x${value.toString(16)}`;
}

async function runAnvilCommand(arguments_: readonly string[]): Promise<string> {
  const process = Bun.spawn([ANVIL_BIN, ...arguments_], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    process.exited,
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
  ]);
  if (exitCode !== 0) {
    throw new Error(
      `${ANVIL_BIN} ${arguments_.join(" ")} failed with exit code ${exitCode}:\n${stderr}`,
    );
  }
  return `${stdout}\n${stderr}`;
}

function assertSupportedAnvil(versionOutput: string, helpOutput: string): void {
  const match = versionOutput.match(/Version:\s*(\d+)\.(\d+)\.(\d+)/);
  if (!match) {
    throw new Error(`could not parse Anvil version from:\n${versionOutput}`);
  }

  const version = match.slice(1, 4).map(Number);
  for (let i = 0; i < MINIMUM_ANVIL_VERSION.length; i++) {
    if (version[i] > MINIMUM_ANVIL_VERSION[i]) break;
    if (version[i] < MINIMUM_ANVIL_VERSION[i]) {
      throw new Error(
        `Anvil 1.8.0 or newer is required, found ${version.join(".")}`,
      );
    }
  }

  if (!/possible values:[^\]]*\bmonad\b/s.test(helpOutput)) {
    throw new Error(
      `${ANVIL_BIN} ${version.join(".")} was built without Monad support; use an official Foundry release artifact`,
    );
  }
}

async function getAvailablePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  const address = server.address();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  if (!address || typeof address === "string") {
    throw new Error("failed to reserve a local TCP port");
  }
  return address.port;
}

async function rpc<T>(
  rpcUrl: string,
  method: string,
  params: readonly unknown[] = [],
): Promise<T> {
  const id = ++requestId;
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });
  if (!response.ok) {
    throw new Error(`${method} returned HTTP ${response.status}`);
  }

  const payload = (await response.json()) as JsonRpcResponse<T>;
  if ("error" in payload) {
    throw new Error(
      `${method} failed (${payload.error.code}): ${payload.error.message}`,
    );
  }
  return payload.result;
}

async function startAnvil(): Promise<{
  rpcUrl: string;
  stop(): Promise<void>;
}> {
  const port = await getAvailablePort();
  const rpcUrl = `http://127.0.0.1:${port}`;
  const process = Bun.spawn(
    [
      ANVIL_BIN,
      "--network",
      "monad",
      "--hardfork",
      "MonadNine",
      "--host",
      "127.0.0.1",
      "--port",
      String(port),
      "--quiet",
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
  const output = Promise.all([
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
  ]).then(([stdout, stderr]) => `${stdout}\n${stderr}`);

  const stop = async (): Promise<void> => {
    if (process.exitCode === null) process.kill();
    const exited = await Promise.race([
      process.exited.then(() => true),
      Bun.sleep(2_000).then(() => false),
    ]);
    if (!exited) {
      process.kill(9);
      await process.exited;
    }
    await output;
  };

  let lastError: unknown;
  for (let attempt = 0; attempt < 100; attempt++) {
    if (process.exitCode !== null) break;
    try {
      await rpc<string>(rpcUrl, "eth_chainId");
      return { rpcUrl, stop };
    } catch (error) {
      lastError = error;
      await Bun.sleep(50);
    }
  }

  await stop();
  throw new Error(
    `Monad-mode Anvil did not start: ${String(lastError)}\n${await output}`,
  );
}

async function waitForReceipt(
  rpcUrl: string,
  transactionHash: string,
): Promise<TransactionReceipt> {
  for (let attempt = 0; attempt < 100; attempt++) {
    const receipt = await rpc<TransactionReceipt | null>(
      rpcUrl,
      "eth_getTransactionReceipt",
      [transactionHash],
    );
    if (receipt) return receipt;
    await Bun.sleep(50);
  }
  throw new Error(`timed out waiting for transaction ${transactionHash}`);
}

async function deployStorageContract(
  rpcUrl: string,
  sender: string,
): Promise<string> {
  const transactionHash = await rpc<string>(rpcUrl, "eth_sendTransaction", [
    {
      from: sender,
      data: STORAGE_CONTRACT_INIT_CODE,
      gas: "0x100000",
    },
  ]);
  const receipt = await waitForReceipt(rpcUrl, transactionHash);
  expect(receipt.status).toBe("0x1");
  if (!receipt.contractAddress)
    throw new Error("deployment returned no address");
  return receipt.contractAddress;
}

async function writeStorage(
  rpcUrl: string,
  sender: string,
  contract: string,
  key: Uint8Array,
  value: Uint8Array,
): Promise<void> {
  const calldata = new Uint8Array(SLOT_SIZE * 2);
  calldata.set(key);
  calldata.set(value, SLOT_SIZE);
  const transactionHash = await rpc<string>(rpcUrl, "eth_sendTransaction", [
    {
      from: sender,
      to: contract,
      data: bytesToHex(calldata),
      gas: "0x100000",
    },
  ]);
  const receipt = await waitForReceipt(rpcUrl, transactionHash);
  expect(receipt.status).toBe("0x1");
}

async function readStorage(
  rpcUrl: string,
  contract: string,
  slot: bigint,
): Promise<Uint8Array> {
  const value = await rpc<string>(rpcUrl, "eth_getStorageAt", [
    contract,
    toQuantity(slot),
    "latest",
  ]);
  return hexToWord(value);
}

test("mirrors contract storage from Anvil --network monad", async () => {
  const [versionOutput, helpOutput] = await Promise.all([
    runAnvilCommand(["--version"]),
    runAnvilCommand(["--help"]),
  ]);
  assertSupportedAnvil(versionOutput, helpOutput);

  const anvil = await startAnvil();
  try {
    const [sender] = await rpc<string[]>(anvil.rpcUrl, "eth_accounts");
    if (!sender) throw new Error("Anvil returned no unlocked account");
    const contract = await deployStorageContract(anvil.rpcUrl, sender);
    const maximumSlot = (1n << 256n) - 1n;
    const entries = [
      [0n, 1n],
      [127n, 2n],
      [128n, 3n],
      [255n, 4n],
      [maximumSlot, 5n],
    ] as const;

    const operations: PageTrieBatchOperation[] = [];
    for (const [slot, value] of entries) {
      const key = uint256(slot);
      await writeStorage(anvil.rpcUrl, sender, contract, key, uint256(value));
      const observed = await readStorage(anvil.rpcUrl, contract, slot);
      expect(observed).toEqual(uint256(value));
      operations.push({ type: "put", key, value: observed });
    }

    const trie = await createPageTrie();
    await trie.batch(operations);
    for (const [slot, value] of entries) {
      expect(await trie.get(uint256(slot))).toEqual(uint256(value));
    }

    const initialRoot = trie.root();
    await writeStorage(
      anvil.rpcUrl,
      sender,
      contract,
      uint256(128n),
      uint256(9n),
    );
    await trie.put(
      uint256(128n),
      await readStorage(anvil.rpcUrl, contract, 128n),
    );
    expect(trie.root()).not.toEqual(initialRoot);

    await writeStorage(
      anvil.rpcUrl,
      sender,
      contract,
      uint256(128n),
      uint256(3n),
    );
    await trie.put(
      uint256(128n),
      await readStorage(anvil.rpcUrl, contract, 128n),
    );
    expect(trie.root()).toEqual(initialRoot);

    await writeStorage(
      anvil.rpcUrl,
      sender,
      contract,
      uint256(127n),
      new Uint8Array(SLOT_SIZE),
    );
    const deleted = await readStorage(anvil.rpcUrl, contract, 127n);
    expect(deleted).toEqual(new Uint8Array(SLOT_SIZE));
    await trie.put(uint256(127n), deleted);
    expect(await trie.get(uint256(127n))).toBeNull();
  } finally {
    await anvil.stop();
  }
}, 30_000);
