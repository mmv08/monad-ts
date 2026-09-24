# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Monorepo Structure

This is a bun workspaces monorepo. Packages live under `packages/`.

| Package | Path |
| --- | --- |
| `@monad-crypto/viem` | `packages/viem/` |
| `@monad-crypto/mpp` | `packages/mpp/` |
| `@monad-crypto/btx` | `packages/btx/` (private, not published) |

## Commands

```bash
# Root (all packages)
bun run build                         # Build all packages
bun run lint                          # Lint and format check (biome)
bun run test                          # Run tests in all packages
bun run typecheck                     # Type-check all packages

# Package-level (from repo root)
bun test --cwd packages/viem          # Run tests for @monad-crypto/viem
bun run --cwd packages/viem build     # Build @monad-crypto/viem
bun run --cwd packages/viem typecheck # Type-check @monad-crypto/viem

# BTX package (pure, no network)
bun test --cwd packages/btx --coverage           # Run @monad-crypto/btx tests with coverage
bun run --cwd packages/btx typecheck             # Type-check @monad-crypto/btx
bun run packages/btx/tests/fixtures/generate.ts  # Regenerate BTX fixture vectors after a scheme change
```

## Conventions

- Use bun as the package manager and runtime (not npm/yarn/node).
- JSDoc on each action in the `MonadActions` decorator type (`packages/viem/src/decorator.ts`) must exactly match the JSDoc on the corresponding action's implementation function.
- Formatting: 2-space indent, double quotes (enforced by Biome).
- All imports use `.js` extensions (ESM with `verbatimModuleSyntax`).
- When adding, removing, or changing actions, contracts, constants, or trust boundaries, update `packages/viem/ARCHITECTURE.md` to reflect the change (e.g. the action inventory table, hardcoded constants table, or security scope).
- In `packages/btx`, the PDF specification (`encrypted_txs_specs_wip.pdf`, BTX section) is the authority; the Rust and CatBlst implementations are references only. Mark anything the PDF leaves open with a `TODO(spec)` comment and list it in `packages/btx/ARCHITECTURE.md`.
- Never import `packages/btx/src/testing.ts` from `packages/btx/src/index.ts` or any sender code; it holds the trapdoor and is insecure by design.
- When a BTX constant, encoding, or hash transcript changes, regenerate `packages/btx/tests/fixtures/vectors.json` with the generator script and update `packages/btx/ARCHITECTURE.md`.

## Architecture

`@monad-crypto/viem` is a Viem extension library providing read actions for the Monad staking precompile and WMON token.

### Dual API surface

The library exposes two ways to call every action:

1. **Namespace imports** — standalone functions: `Staking.getValidator(client, params)`, `Wmon.getBalanceOf(client, params)`
2. **Client decorator** — `monadActions()` extends a Viem client so actions are called as `client.staking.getValidator(params)`, `client.wmon.getBalanceOf(params)`

Both paths call the same implementation function.

### Key files

- `packages/viem/src/constants.ts` — ABIs (`stakingAbi`, `wmonAbi`) and contract addresses/metadata. All actions import from here.
- `packages/viem/src/decorator.ts` — `MonadActions` type (the decorator shape with JSDoc) and `monadActions()` factory that wires actions to the client.
- `packages/viem/src/actions/staking/index.ts`, `packages/viem/src/actions/wmon/index.ts` — namespace barrel files that re-export actions and also alias constants (e.g. `STAKING_ADDRESS as ADDRESS`).
- `packages/viem/src/index.ts` — top-level entry: re-exports `Staking` and `Wmon` namespaces plus decorator.
- `packages/viem/ARCHITECTURE.md` — security-focused architecture documentation for auditors and AI agents.

### Action pattern

Every action file (e.g. `packages/viem/src/actions/staking/getValidator.ts`) follows the same structure:
1. Define `Parameters`, `ReturnType`, and `ErrorType` types derived from Viem's `ReadContractParameters`/`ReadContractReturnType`, omitting `abi`, `address`, and `functionName`.
2. Export an `async function` that calls `readContract` with the fixed ABI, address, and function name.

### Adding a new action

1. Create `packages/viem/src/actions/<module>/<actionName>.ts` following the existing pattern.
2. Create `packages/viem/src/actions/<module>/<actionName>.test.ts` with an inline snapshot test against the live RPC (use `FORK_BLOCK_NUMBER` from `packages/viem/test/setup.ts` for determinism).
3. Re-export from `packages/viem/src/actions/<module>/index.ts`.
4. Wire into `packages/viem/src/decorator.ts`: add the import, add the JSDoc-annotated method to `MonadActions` type, and add the implementation to `monadActions()`.

### Tests

Tests run against Monad mainnet RPC (`https://rpc.monad.xyz`) using `bun:test`. Most use `toMatchInlineSnapshot` at a pinned `FORK_BLOCK_NUMBER` for deterministic assertions.

## BTX Architecture

`@monad-crypto/btx` is the sender-side implementation of the BTX threshold encryption scheme for encrypted transactions. It works on `Uint8Array` values only and knows nothing about transactions or RPC.

- `packages/btx/src/curve.ts` wraps `@noble/curves` BLS12-381: canonical G_1, scalar, and G_T codecs.
- `packages/btx/src/hash.ts` implements the Blake3 primitives of the specification's Appendix E and the proof challenge.
- `packages/btx/src/ciphertext.ts` defines the `Ciphertext` type and its one canonical wire form.
- `packages/btx/src/btx.ts` implements padding, the Schnorr proof, `encrypt`, `admitCiphertext`, and `verifyDecryption`. Encryption and witness verification take named parameter objects. Admission and test decryption accept only wire bytes and decode and verify once. The split decoder stays internal for format tests. Decoded values stay local to each call because public ciphertext arrays remain mutable.
- `packages/btx/src/index.ts` is the complete public surface; `packages/btx/src/testing.ts` is the separate `@monad-crypto/btx/testing` entry with trapdoor-based test keys.
- Public `encrypt` always uses the platform CSPRNG. Only fixtures and tests call the internal `encryptWithRandom` or `encryptPadded` helpers with injected randomness.
- `packages/btx/tests/` holds pure `bun:test` suites and the fixture vectors with their generator.
- `packages/btx/ARCHITECTURE.md` documents constants, encodings, error mapping, dependencies, and specification gaps.

Tests need no network and no anvil. The root `bunfig.toml` enforces 100% line and function coverage.
