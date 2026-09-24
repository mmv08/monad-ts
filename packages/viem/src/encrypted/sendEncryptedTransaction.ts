import { encrypt, serializeCiphertext } from "@monad-crypto/btx";
import {
  type Account,
  assertRequest,
  type BaseError,
  bytesToHex,
  type Chain,
  type Client,
  type Hash,
  type Hex,
  hexToBytes,
  InvalidAddressError,
  keccak256,
  MaxFeePerGasTooLowError,
  type Transport,
} from "viem";
import {
  estimateFeesPerGas,
  getChainId,
  getTransactionCount,
  sendRawTransaction,
} from "viem/actions";
import {
  associatedData,
  conceal,
  type Envelope,
  encodePayload,
  maskFor,
  type Payload,
  serializeTransaction,
} from "./codec.js";
import { EncryptedTransactionError } from "./errors.js";
import type {
  EncryptionContext,
  SendEncryptedTransactionParameters,
  SendEncryptedTransactionReturnType,
} from "./types.js";

/**
 * Encrypts and signs locally, then submits one type-8 transaction.
 * Requires gas; never estimates or sends plaintext to the RPC.
 * @returns The original signed transaction hash.
 */
export async function sendEncryptedTransaction<
  transport extends Transport,
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<transport, chain, account>,
  parameters: SendEncryptedTransactionParameters<account>,
): Promise<SendEncryptedTransactionReturnType> {
  const { contextProvider, gas, paddedLength, to } = parameters;
  const account = parameters.account ?? client.account;
  // Viem does not export its account errors, so this one is ETX-specific.
  if (account?.type !== "local")
    throw new EncryptedTransactionError(
      "unsupportedSigner",
      "A local secp256k1 account is required.",
    );
  // An omitted recipient must never become contract creation; that takes `to: null`.
  if (to !== null && !to) throw new InvalidAddressError({ address: to });
  assertRequest({ ...parameters, account });
  const payload: Payload = {
    to,
    value: parameters.value ?? 0n,
    data: parameters.data ?? "0x",
    accessList: parameters.accessList ?? [],
  };
  const encryptedFields = maskFor(parameters.encryptedFields);
  const plaintext = hexToBytes(encodePayload(payload, encryptedFields));

  // The steps below follow viem's prepareTransactionRequest for local accounts.
  // Viem's version cannot be used: it may send the request to eth_fillTransaction.
  const chainId = client.chain?.id ?? (await getChainId(client));
  let { maxFeePerGas, maxPriorityFeePerGas } = parameters;
  if (maxFeePerGas === undefined || maxPriorityFeePerGas === undefined) {
    // Viem forwards `request` to the estimator and fee hooks, although the
    // action's type omits it. It carries public fields only.
    const feeParameters = {
      chain: client.chain,
      request: { chainId, gas, maxFeePerGas, maxPriorityFeePerGas },
    };
    const fees = await estimateFeesPerGas(client, feeParameters);
    if (
      maxPriorityFeePerGas === undefined &&
      maxFeePerGas &&
      maxFeePerGas < fees.maxPriorityFeePerGas
    )
      throw new MaxFeePerGasTooLowError({
        maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
      });
    ({ maxFeePerGas, maxPriorityFeePerGas } = fees);
    assertRequest({ maxFeePerGas, maxPriorityFeePerGas });
  }

  const context = contextProvider
    ? await contextProvider({ chainId, account: account.address })
    : await client.request<{
        Method: "monad_getEncryptionContext";
        Parameters: [];
        ReturnType: EncryptionContext<Hex>;
      }>({ method: "monad_getEncryptionContext", params: [] });
  if (!context.available)
    throw new EncryptedTransactionError(
      "unavailable",
      "Encryption is unavailable for the active epoch.",
    );
  const epoch = BigInt(context.epoch);
  const nonceManager =
    parameters.nonce === undefined ? account.nonceManager : undefined;
  const nonce =
    parameters.nonce ??
    (nonceManager
      ? await nonceManager.consume({
          address: account.address,
          chainId,
          client,
        })
      : await getTransactionCount(client, {
          address: account.address,
          blockTag: "pending",
        }));
  const envelope: Envelope = {
    type: "encrypted",
    chainId,
    nonce,
    gas,
    maxFeePerGas,
    maxPriorityFeePerGas,
    ...conceal(payload, encryptedFields),
    epoch,
    encryptedFields,
    ciphertext: "0x",
  };
  let serializedTransaction: Hex;
  try {
    envelope.ciphertext = bytesToHex(
      serializeCiphertext(
        encrypt({
          plaintext,
          encryptionKey: hexToBytes(context.encryptionKey),
          associatedData: hexToBytes(associatedData(envelope, account.address)),
          paddedLength,
        }),
      ),
    );
    serializedTransaction = await account.signTransaction(envelope, {
      serializer: serializeTransaction,
    });
  } catch (error) {
    // As in viem, a send that fails before submission hands its nonce back.
    nonceManager?.reset({ address: account.address, chainId });
    throw error;
  }

  const hash = keccak256(serializedTransaction);
  let returnedHash: Hash;
  try {
    returnedHash = await sendRawTransaction(client, { serializedTransaction });
  } catch (error) {
    // Viem wraps every request failure in a BaseError. Only a structured backend
    // reason among its causes proves rejection; any other failure may follow acceptance.
    const cause = error as BaseError;
    const reason = reasonOf(
      cause.walk((error) => reasonOf(error) !== undefined),
    );
    const options = { hash, cause };
    if (reason === undefined)
      throw new EncryptedTransactionError(
        "unknownOutcome",
        "Submission outcome is unknown; look up the original hash before taking further action.",
        options,
      );
    throw new EncryptedTransactionError(
      reason === "expiredEpoch" ? "expiredEpoch" : "rejected",
      "The backend rejected the encrypted transaction.",
      options,
    );
  }
  if (returnedHash.toLowerCase() !== hash)
    throw new EncryptedTransactionError(
      "unknownOutcome",
      "RPC returned a different transaction hash.",
      { hash },
    );
  return hash;
}

function reasonOf(error: unknown): string | undefined {
  const reason = (error as { data?: { reason?: unknown } } | null)?.data
    ?.reason;
  return typeof reason === "string" ? reason : undefined;
}
