# Phase 2: encrypted transactions for viem

**Status:** implemented as an internal reference, 24 September 2026. [ENCRYPTED.md](./ENCRYPTED.md) describes the API and commands, and the encrypted section of [ARCHITECTURE.md](./ARCHITECTURE.md) describes the trust boundaries.

**Authority:** the [parent delivery plan](../../../encrypted-transactions-plan.md) and the [protocol PDF](../../../encrypted_txs_specs_wip.pdf). The PDF sets protocol rules. This plan only gives direction; technical details live in the code, its tests, and the two documents above.

## Goal

A developer can build from Git, configure an ordinary viem local account and transport, send an encrypted transfer or contract call, and read typed transactions and receipts, all against a local mock and without a live network.

## Direction

- **Build on viem.** If viem, Ox or BTX already does something, use it; do not add a layer on top. Follow viem's conventions for actions, decorators, chain formatters, errors and retries. Skip plan requirements that lack a correctness or security reason for departing from those defaults. Where viem's own function cannot be used, mirror its steps.
- **One explicit action.** A single send action, with a decorator, is the whole write API. Leave ordinary `sendTransaction` alone: its preparation can send the plaintext to a node.
- **Privacy first.** Never estimate, simulate or fill a transaction against a remote node, never send plaintext, and never fall back to an ordinary transaction. The caller supplies gas.
- **Keep viem's submission behavior.** Fallback transports may send identical signed bytes to another endpoint; the hash and nonce stay the same. Do not automatically re-encrypt or re-sign after failure, which could create a different transaction. Report submission failures as `unknownOutcome` with the local hash and original cause: a rejection from one backend does not rule out acceptance by another.
- **A small, pure codec.** Encode, bind and serialize the envelope. Leave received-byte parsing to the backends.
- **Validate only what nothing else does.** Keep checks for protocol rules the libraries cannot know, such as an explicit creation request or a nonempty field selection. Everything else belongs to viem, Ox or BTX.
- **Ordinary queries.** Chain formatters give ETX types to viem's normal transaction, block and receipt actions.
- **A mock, not a node.** The mock admits real signed bytes, decrypts them, and scripts receipts. It holds only what the client tests need.
- **Tests with signal.** Test the ETX code rather than its dependencies: the PDF's field table, a committed vector, privacy, lifecycle outcomes and consumer builds.

## Out of scope

EVM execution (Phase 3, in Anvil), comparison with a real node (Phase 4), external wallets, and public package releases.
