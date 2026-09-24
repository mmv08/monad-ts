import type { Account, Chain, Client, Transport } from "viem";
import { sendEncryptedTransaction } from "./sendEncryptedTransaction.js";
import type {
  EncryptedWalletActionsParameters,
  SendEncryptedTransactionParameters,
  SendEncryptedTransactionReturnType,
} from "./types.js";

export type EncryptedWalletActions<
  account extends Account | undefined = undefined,
> = {
  /**
   * Encrypts and signs locally, then submits one type-8 transaction.
   * Requires gas; never estimates or sends plaintext to the RPC.
   * @returns The original signed transaction hash.
   */
  sendEncryptedTransaction: (
    parameters: SendEncryptedTransactionParameters<account>,
  ) => Promise<SendEncryptedTransactionReturnType>;
};

/** Adds the encrypted send action to a viem client. A `contextProvider` given here is the default for each send. */
export function encryptedWalletActions({
  contextProvider,
}: EncryptedWalletActionsParameters = {}) {
  return <
    transport extends Transport,
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    client: Client<transport, chain, account>,
  ): EncryptedWalletActions<account> => ({
    sendEncryptedTransaction: (parameters) =>
      sendEncryptedTransaction(client, { contextProvider, ...parameters }),
  });
}
