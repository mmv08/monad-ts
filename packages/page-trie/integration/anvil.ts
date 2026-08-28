import { expect, test } from "bun:test";

import {
  createPageTrie,
  type PageTrieBatchOperation,
  SLOT_SIZE,
} from "../src/index.js";
import { bytesToHex } from "../src/page.js";
import { uint256 } from "../testing/utils.js";

const RPC_URL = process.env.ANVIL_RPC_URL ?? "";
if (!RPC_URL) {
  throw new Error(
    "ANVIL_RPC_URL is not set; run scripts/run_integration_tests.sh",
  );
}

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

function toQuantity(value: bigint): `0x${string}` {
  return `0x${value.toString(16)}`;
}

async function rpc<T>(
  method: string,
  params: readonly unknown[] = [],
): Promise<T> {
  const id = ++requestId;
  const response = await fetch(RPC_URL, {
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

async function waitForReceipt(
  transactionHash: string,
): Promise<TransactionReceipt> {
  for (let attempt = 0; attempt < 100; attempt++) {
    const receipt = await rpc<TransactionReceipt | null>(
      "eth_getTransactionReceipt",
      [transactionHash],
    );
    if (receipt) return receipt;
    await Bun.sleep(50);
  }
  throw new Error(`timed out waiting for transaction ${transactionHash}`);
}

async function deployStorageContract(sender: string): Promise<string> {
  const transactionHash = await rpc<string>("eth_sendTransaction", [
    {
      from: sender,
      data: STORAGE_CONTRACT_INIT_CODE,
      gas: "0x100000",
    },
  ]);
  const receipt = await waitForReceipt(transactionHash);
  expect(receipt.status).toBe("0x1");
  if (!receipt.contractAddress)
    throw new Error("deployment returned no address");
  return receipt.contractAddress;
}

async function writeStorage(
  sender: string,
  contract: string,
  key: Uint8Array,
  value: Uint8Array,
): Promise<void> {
  const calldata = new Uint8Array(SLOT_SIZE * 2);
  calldata.set(key);
  calldata.set(value, SLOT_SIZE);
  const transactionHash = await rpc<string>("eth_sendTransaction", [
    {
      from: sender,
      to: contract,
      data: `0x${bytesToHex(calldata)}`,
      gas: "0x100000",
    },
  ]);
  const receipt = await waitForReceipt(transactionHash);
  expect(receipt.status).toBe("0x1");
}

async function readStorage(
  contract: string,
  slot: bigint,
): Promise<Uint8Array> {
  const value = await rpc<string>("eth_getStorageAt", [
    contract,
    toQuantity(slot),
    "latest",
  ]);
  return hexToWord(value);
}

test("mirrors contract storage from Anvil --network monad", async () => {
  const [sender] = await rpc<string[]>("eth_accounts");
  if (!sender) throw new Error("Anvil returned no unlocked account");
  const contract = await deployStorageContract(sender);
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
    await writeStorage(sender, contract, key, uint256(value));
    const observed = await readStorage(contract, slot);
    expect(observed).toEqual(uint256(value));
    operations.push({ type: "put", key, value: observed });
  }

  const trie = await createPageTrie();
  await trie.batch(operations);
  for (const [slot, value] of entries) {
    expect(await trie.get(uint256(slot))).toEqual(uint256(value));
  }

  const initialRoot = trie.root();
  await writeStorage(sender, contract, uint256(128n), uint256(9n));
  await trie.put(uint256(128n), await readStorage(contract, 128n));
  expect(trie.root()).not.toEqual(initialRoot);

  await writeStorage(sender, contract, uint256(128n), uint256(3n));
  await trie.put(uint256(128n), await readStorage(contract, 128n));
  expect(trie.root()).toEqual(initialRoot);

  await writeStorage(
    sender,
    contract,
    uint256(127n),
    new Uint8Array(SLOT_SIZE),
  );
  const deleted = await readStorage(contract, 127n);
  expect(deleted).toEqual(new Uint8Array(SLOT_SIZE));
  await trie.put(uint256(127n), deleted);
  expect(await trie.get(uint256(127n))).toBeNull();
}, 30_000);
