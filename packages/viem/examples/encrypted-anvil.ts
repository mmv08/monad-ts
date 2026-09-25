// Sends encrypted transactions to Monad Anvil, which decrypts them with its test key and runs them
// on the EVM. Start Anvil from the Foundry fork first:
//
//   anvil --network monad --monad.encrypted-transactions
import {
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  numberToHex,
  parseEther,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  encryptedFormatters,
  encryptedWalletActions,
} from "../src/encrypted/index.js";

const url = process.env.ANVIL_URL ?? "http://127.0.0.1:8545";
const transport = http(url);
const chain = defineChain({
  id: await createPublicClient({ transport }).getChainId(),
  name: "Monad Anvil",
  nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
  rpcUrls: { default: { http: [url] } },
  formatters: encryptedFormatters,
  supportsTransactionReplacementDetection: false,
});
// Anvil's first development account. Test key only.
const account = privateKeyToAccount(
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
);
const wallet = createWalletClient({ account, chain, transport }).extend(
  encryptedWalletActions(),
);
const client = createPublicClient({ chain, transport });

// An ordinary deployment of a contract that stores its first calldata word in slot 0.
const { contractAddress: contract } = await client.waitForTransactionReceipt({
  hash: await wallet.sendTransaction({
    data: "0x666000356000550060005260076019f3",
  }),
});
if (!contract) throw new Error("Deployment failed");

const recipient = "0x1111111111111111111111111111111111111111";
for (const request of [
  { to: recipient, value: parseEther("1"), gas: 21_000n },
  { to: contract, data: numberToHex(42n, { size: 32 }), gas: 100_000n },
] as const) {
  const hash = await wallet.sendEncryptedTransaction(request);
  const receipt = await client.waitForTransactionReceipt({ hash });
  const { to } = await client.getTransaction({ hash });
  const decryption =
    receipt.type === "encrypted" ? receipt.decryptionStatus : undefined;
  console.log(`${hash} to ${to}: ${receipt.status}, decryption ${decryption}`);
}

console.log(
  "Recipient balance:",
  await client.getBalance({ address: recipient }),
);
const stored = await client.getStorageAt({ address: contract, slot: "0x0" });
console.log("Stored value:", BigInt(stored ?? "0x0"));
