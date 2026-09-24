import {
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  encryptedFormatters,
  encryptedWalletActions,
} from "../src/encrypted/index.js";

const chain = defineChain({
  id: 1337,
  name: "ETX local mock",
  nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
  rpcUrls: { default: { http: ["http://127.0.0.1:8545/rpc"] } },
  formatters: encryptedFormatters,
  supportsTransactionReplacementDetection: false,
});
const transport = http(chain.rpcUrls.default.http[0]);
const wallet = createWalletClient({
  account: privateKeyToAccount(generatePrivateKey()),
  chain,
  transport,
}).extend(encryptedWalletActions());
const publicClient = createPublicClient({ chain, transport });

// Expose only a result for the tiny HTML example. All signing runs in the browser.
const result = await (async () => {
  try {
    const hash = await wallet.sendEncryptedTransaction({
      to: "0x1111111111111111111111111111111111111111",
      value: 1n,
      gas: 21_000n,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    return `Scripted receipt: ${receipt.status}\nHash: ${hash}\nNo EVM execution or threshold privacy.`;
  } catch (error) {
    return error instanceof Error ? error.message : "Example failed";
  }
})();
// This source compiles with the package's non-DOM tsconfig too.
console.log(result);
export { result };
