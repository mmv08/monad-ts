import {
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  erc20Abi,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { encryptedWalletActions } from "../src/encrypted/index.js";
import { chain, createMock } from "../test/encrypted/mock.js";

const mock = createMock();
const account = privateKeyToAccount(`0x${"01".repeat(32)}`);
const wallet = createWalletClient({
  account,
  chain,
  transport: mock.transport,
}).extend(encryptedWalletActions());
const client = createPublicClient({ chain, transport: mock.transport });
const to = "0x1111111111111111111111111111111111111111";

for (const data of [
  "0x",
  encodeFunctionData({
    abi: erc20Abi,
    functionName: "transfer",
    args: [to, 100n],
  }),
] as const) {
  const hash = await wallet.sendEncryptedTransaction({
    to,
    value: 1n,
    data,
    gas: 100_000n,
  });
  console.log("Mock accepted:", hash);
  mock.include(hash);
  const receipt = await client.waitForTransactionReceipt({
    hash,
    checkReplacement: false,
    retryCount: 2,
  });
  console.log("Scripted receipt (no EVM execution):", receipt.status);
}
