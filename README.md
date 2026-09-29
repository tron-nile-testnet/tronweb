<h1 align="center">
  <a href="https://tronweb.network">
    <img align="center" src="https://raw.githubusercontent.com/tronprotocol/tronweb/master/assets/logo.png"/>
  </a>
</h1>

<p align="center">
  <a href="https://discord.gg/FgvVFQgdCW">
    <img src="https://img.shields.io/badge/chat-on%20discord-brightgreen.svg">
  </a>

  <a href="https://github.com/tronprotocol/tronweb/issues">
    <img src="https://img.shields.io/github/issues/tron-us/tronweb.svg">
  </a>

  <a href="https://github.com/tronprotocol/tronweb/pulls">
    <img src="https://img.shields.io/github/issues-pr/tron-us/tronweb.svg">
  </a>

  <a href="https://github.com/tronprotocol/tronweb/graphs/contributors">
    <img src="https://img.shields.io/github/contributors/tron-us/tronweb.svg">
  </a>

  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/tron-us/tronweb.svg">
  </a>
</p>

> **This is a fork.** This repository ([tron-nile-testnet/tronweb](https://github.com/tron-nile-testnet/tronweb)) is maintained by the **tron-nile-testnet** organization to give community developers a JavaScript SDK for TRON's post-quantum (PQ) signature upgrade on the **Nile testnet** — Falcon-512 (`FN_DSA_512`) transaction signing is active on Nile today. The upstream [tronprotocol/tronweb](https://github.com/tronprotocol/tronweb) package is not affected by this work.
>
> This fork is **not published to npm** — `npm install tronweb` gives you the upstream package, which has no PQ support. Install it from GitHub by git ref (the `prepare` script builds the library during install), from the packed `.tgz` attached to a release, or from a local clone; [Installation](#installation) covers all three. The one-liner:
>
> ```bash
> npm install github:tron-nile-testnet/tronweb#pq_sig
> ```
>
> Any branch, tag or commit works as the `#ref`. The package name stays `tronweb`, so it lands in `node_modules/tronweb` as a drop-in replacement for the upstream library (current version: `6.5.1-pq-nile.0`). See [Post-Quantum Signatures (Nile)](#post-quantum-signatures-nile) for the full guide.

## What is TronWeb?

[TronWeb](https://tronweb.network) aims to deliver a unified, seamless development experience for the TRON ecosystem. We have taken the core ideas and expanded upon them to unlock the functionality of TRON's unique feature set along with offering new tools for integrating DApps in the browser, Node.js and IoT devices.

To better support its use in TypeScript projects, we have rewritten the entire library in TypeScript. And to make the TronWeb API more secure and consistent, there are some breaking changes. <font color=red>Please check out [<font color=red>6.x API documentation</font>](https://tronweb.network/docu/docs/intro/)</font> for detailed changes so you can start using the new TypeScript version of TronWeb early. Any questions or feedback are welcome [here](https://github.com/tronprotocol/tronweb/issues/new).

**Project scope**

Any new TRON feature will be incorporated into TronWeb. Changes to the API to improve quality-of-life are in-scope for the project. We are committed to keeping TronWeb up-to-date with the latest developments in the TRON ecosystem while continuously refining the developer experience.

## HomePage

__[tronweb.network](https://tronweb.network)__

## Compatibility
- Version built for Node.js v14 and above — the `tronweb/pq` entry point needs Node.js 20.19+ / 22.12+ / 23+ (see [Network, fees and runtime requirements](#network-fees-and-runtime-requirements)), and installing from a git ref runs the build on your machine, which needs Node.js 20 or 22+ (see [Installation](#installation))
- Version built for browsers with more than 0.25% market share

You can access either version specifically from the dist folder.

TronWeb is also compatible with frontend frameworks such as:
- Angular
- React
- Vue.

You can also ship TronWeb in a Chrome extension.

## Recent History

For recent history, see the [CHANGELOG](CHANGELOG.md) — the `6.5.1-pq-nile.0` entry lists this fork's changes; the entries below it are inherited from upstream. You can check it out for:
- New features
- Dependencies update
- Bug fix

## Installation

This fork is **not published to npm**, so `npm install tronweb` / `yarn add tronweb` install the upstream package — no `tronweb/pq`, none of the changes listed in the [CHANGELOG](CHANGELOG.md). Get it one of these three ways instead. Whichever you pick, the package lands in `node_modules/tronweb`, so `import ... from 'tronweb'` and `'tronweb/pq'` work as written in the examples below. The commands use npm; other package managers accept the same specifiers, provided they run the package's `prepare` script for git dependencies.

### From GitHub by git ref (branch, tag or commit)

```bash
npm install github:tron-nile-testnet/tronweb#pq_sig            # the branch
npm install github:tron-nile-testnet/tronweb#<tag-or-commit>   # a release tag or a specific commit
```

npm clones the repository at that ref, installs its build dependencies and runs the `prepare` script, which builds `lib/` (CommonJS + ESM) and `dist/` before the package is installed. Allow several minutes: cloning the repository history dominates (about six minutes from GitHub on an ordinary connection; the build itself takes well under a minute), and have `git` on the `PATH` and Node.js 20 or 22+ to run the build. The lockfile pins the resolved commit, so later installs reproduce the same build. The build only happens when install scripts are allowed: npm 11 prints an advisory `allow-scripts` warning naming `tronweb` (the script still runs), but with `ignore-scripts=true` in your npm config the install exits 0 with `node_modules/tronweb` containing only `src/`, and every `require`/`import` fails with `Cannot find module '.../lib/commonjs/index.js'`.

### From a release

Each [release](https://github.com/tron-nile-testnet/tronweb/releases) attaches the packed package, `tronweb-<version>.tgz` — the output of `npm pack`, with `lib/` and `dist/` already built. Install it by path or by URL; no build, git or install scripts are involved:

```bash
npm install ./tronweb-6.5.1-pq-nile.0.tgz
npm install https://github.com/tron-nile-testnet/tronweb/releases/download/<tag>/tronweb-<version>.tgz
```

Do **not** install the release page's auto-generated *Source code* archives (`.zip` / `.tar.gz`): npm runs no build for tarball installs, the install succeeds silently, and `require('tronweb')` then fails with `Cannot find module '.../node_modules/tronweb/lib/commonjs/index.js'`. If you only have sources, use the git ref or the clone path.

### From a local clone

```bash
git clone --branch pq_sig https://github.com/tron-nile-testnet/tronweb.git
cd tronweb && npm install        # runs prepare: builds lib/ and dist/ (npm run build:all rebuilds after changes)
npm pack                         # → tronweb-6.5.1-pq-nile.0.tgz, install it as above
```

To use the clone directly from another project, `npm install /path/to/tronweb` (a symlink into `node_modules/tronweb`) or `npm link` — requiring the clone by filesystem path does not reach the `tronweb/pq` subpath export.

### Checking what you installed

Read `node_modules/tronweb/package.json` (`"version": "6.5.1-pq-nile.0"`; for a git-ref install `npm ls tronweb` also shows the resolved commit). `TronWeb.version` reports the plain upstream base `6.5.1` on purpose: plugin version gating uses `semver.satisfies`, which a prerelease tag would break.

### Browser

Every install path above yields `node_modules/tronweb/dist/TronWeb.js`, the UMD bundle. Copy it to your working folder:
```
cp node_modules/tronweb/dist/TronWeb.js ./js/tronweb.js
```
so that you can call it in your HTML page as
```
<script src="./js/tronweb.js"></script>
```

There are no npm or CDN (unpkg / jsDelivr) mirrors of this fork — anything they serve under the name `tronweb` is the upstream library. The bundle contains no PQ cryptography: key generation, signing and verification need Node.js or a bundler and the `tronweb/pq` entry point (see [Not supported](#not-supported)).

## Testnet

Nile is a Tron testnet. To use it use the following endpoint:
```
https://nile.trongrid.io
```
Get some Nile TRX at https://nileex.io/join/getJoinPage and play with it.
Anything you do should be explorable on https://nile.tronscan.org

## Post-Quantum Signatures (Nile)

This fork adds opt-in support for TRON's post-quantum signature schemes: **FN_DSA_512** (Falcon-512), activated on Nile, and **ML_DSA_44** (ML-DSA-44 / FIPS 204), implemented but not yet activated on any public TRON network. PQ signatures travel in the transaction's `pq_auth_sig` field alongside (or instead of) `signature`; the signing digest is the unchanged 32-byte `txID`, so `raw_data_hex` and `txID` derivation are untouched.

All PQ cryptography lives in a separate `tronweb/pq` entry point. Applications that do not import it load none of the PQ cryptography (`@noble/post-quantum` is only reachable via `tronweb/pq`); the main entry and browser bundle behave like upstream at runtime — see the [CHANGELOG](CHANGELOG.md) for one type-level difference (`BlockHeader.witness_signature` is now optional).

### Quick start

```javascript
import { TronWeb } from 'tronweb';
import { FnDsa512, createPQSigner, assertSchemeEnabled, verifyPQTransaction } from 'tronweb/pq';

const tronWeb = new TronWeb({ fullHost: 'https://nile.trongrid.io' });

// Addresses are yours to supply — every example below refers to these two
// identifiers rather than hard-coding an address.
const recipientAddress = '<base58 address you are sending to>';
const contractAddress = '<base58 address of the contract you are calling>'; // e.g. a TRC20 token

// 1. Generate a Falcon-512 key pair (or import one — see "Key formats" below)
const key = FnDsa512.generateKeyPair();
console.log(key.address.base58); // T... — fund this address on Nile before sending

// 2. Wrap the key in a signer object
const signer = createPQSigner({ scheme: 'FN_DSA_512', privateKey: key.privateKey });

// 3. Fail fast if the scheme is not activated on the connected network
await assertSchemeEnabled(tronWeb, 'FN_DSA_512');

// 4. Build a transaction owned by the PQ address
const transaction = await tronWeb.transactionBuilder.sendTrx(
    recipientAddress,
    1_000_000, // amount in sun (1 TRX)
    key.address.base58
);

// 5. Sign it — the PQ signature lands in `pq_auth_sig`, not `signature`
const signedTransaction = await tronWeb.trx.signPQ(transaction, signer);

// 6. (Optional) verify locally before broadcasting
const verdict = verifyPQTransaction(signedTransaction, {
    txCheck: tronWeb.utils.transaction.txCheck,
});
console.log(verdict.valid, verdict.txIdMatchesPayload); // true true

// 7. Broadcast
const receipt = await tronWeb.trx.sendRawTransaction(signedTransaction);
console.log(receipt.result, receipt.transaction.txID);
```

`generateKeyPair()` derives a fresh key every run — persist `key.privateKey` if you want the same address next time. For `FN_DSA_512`, persist the 2176-byte private key and **not** the 48-byte seed alone: java-tron marks Falcon seed→key derivation as not bit-stable across platforms (its keygen is FFT-based) and instructs node operators to persist the expanded key for that reason, so a seed re-derived by a different implementation or build may yield a different key — and with it a different address, leaving the funded one unreachable. `ML_DSA_44` (FIPS 204, integer-only keygen) is reproducible from its seed. The address must hold TRX before broadcasting: get Nile TRX from the [faucet](https://nileex.io/join/getJoinPage) and transfer some to the printed address (a plain TRX transfer to a new address also creates the account).

### Supported API surface

- `trx.sign(transaction, signer)` and `trx.multiSign(transaction, signer, permissionId)` accept a `TronPQSigner` object wherever they accept a private-key string. Mixed ECDSA + PQ multisig is supported — weights sum against the same permission threshold (verified end-to-end on a local private network; exercising it on Nile is part of the QA pass).
- `trx.signPQ(transaction, signer, multisig?)` is a dedicated, strictly-typed entry point for the same path: a private-key string here is a compile-time and runtime error, so a PQ call site can never silently fall back to ECDSA.
- `trx.sendRawTransaction()` broadcasts pure-PQ transactions (no `signature` field at all).
- `Trx.getPQSignerAddresses(transaction)` returns the base58 addresses derived from the public keys embedded in `pq_auth_sig` (PQ schemes have no `ecrecover` primitive). `Trx.ecRecover()` reports PQ co-signers on mixed transactions, and on pure-PQ transactions throws an error pointing to `getPQSignerAddresses`.
- The `tronweb/pq` module exports:
  - `FnDsa512` and `MlDsa44` — stateless crypto modules: `generateKeyPair()`, `keyPairFromSeed()`, `keyPairFromPrivateKey()`, `sign()`, `verify()`, `getAddress()`, plus size constants.
  - `createPQSigner({ scheme, privateKey })` — builds a local `TronPQSigner`. The key is validated and the address derived eagerly, so a corrupt or wrong-length key fails at construction, not at sign time.
  - `isTronPQSigner()`, `isSchemeEnabled()` / `assertSchemeEnabled()` (capability detection via `wallet/getchainparameters`), `PQ_CHAIN_PARAM_KEYS`, `PQ_PUBLIC_KEY_SIZES`, `PQ_MAX_TOTAL_SIGNATURES` (the node's cap on `signature` + `pq_auth_sig` combined, 5).
  - `verifyPQTransaction(transaction, options?)` — offline verification of every `pq_auth_sig` entry against the `txID`, with per-entry results. The verdict also grades whether the `txID` belongs to the transaction's payload (`txIdMatchesPayload`: `true` / `false` / `null`) — PQ signatures sign only the txID, so this binding matters. `raw_data_hex` is checked automatically; binding a decoded `raw_data` needs the full re-encode check, injected as `{ txCheck: tronWeb.utils.transaction.txCheck }`. Passing `txCheck` is always safe: on a payload shape it cannot re-encode it grades the binding *uncheckable* (`null`, falling back to the `raw_data_hex` check) rather than disproved, so only a check that ran and disagreed yields `false`. While a decoded `raw_data` is present, `valid` requires that binding to be proven (`txIdMatchesPayload === true`) — verifying a full transaction object without `txCheck` grades `valid: false`, with the per-signature results still reported in `entries`.

A `TronPQSigner` is just `{ scheme, address, publicKey, signDigest(digest) }`, so hardware wallets and remote signers can implement it without exposing key material.

### Key formats

Keys are hex strings or `Uint8Array`s; `keyPairFromPrivateKey` auto-detects the representation by length.

| Scheme | Accepted private-key inputs | Public key | Signature |
| ------ | --------------------------- | ---------- | --------- |
| `FN_DSA_512` | 48-byte seed (derivation input — not a persistence form, see below) · 1280-byte bare key (`f‖g‖F`, the TIP-899 node-key form) · 2176-byte persisted key (`f‖g‖F‖h`, wallet-cli compatible) | 896 bytes | 617–667 bytes (variable) |
| `ML_DSA_44` | 32-byte seed · 2560-byte private key | 1312 bytes | 2420 bytes |

The key and signature formats match java-tron / wallet-cli byte for byte, verified against transactions a PQ-enabled java-tron node accepted — see `test/fixtures/pq-onchain-transactions.json` (five `FN_DSA_512` and three `ML_DSA_44` transfers recorded on a private net; provenance and seeds in `test/pq/onchainFixtures.ts`). Falcon seed→key derivation is a separate matter: `@noble/post-quantum` and BouncyCastle each assert byte-equality against the same round-3 `falcon512-KAT.rsp` seed→key vectors, but that equivalence has not been observed here by running BouncyCastle directly, and java-tron itself marks Falcon keygen as not bit-stable across platforms (`PQSchemeRegistry.seedDeterministic = false`) — so treat the 48-byte seed as a derivation input, not as the persisted form. ML-DSA-44 keygen is reproducible from its seed.

### Smart contract calls

Two ways to send a state-changing contract call from a PQ account:

**1. Wallet-adapter pattern.** `contract.method().send()` signs through `tronWeb.trx.sign`, and its implementation explicitly supports the sign function being replaced — the same mechanism browser wallets use:

```javascript
tronWeb.setAddress(signer.address);
const originalSign = tronWeb.trx.sign.bind(tronWeb.trx);
tronWeb.trx.sign = (transaction) => originalSign(transaction, signer);

const contract = await tronWeb.contract().at(contractAddress);
const txID = await contract
    .transfer(recipientAddress, 1_000_000)
    .send({ feeLimit: 100_000_000 });
```

Capture the original `sign` before replacing it, as above — do not route the replacement through `trx.signPQ`, which itself delegates to `trx.sign` and would recurse.

**2. Manual three-step** — build, sign, broadcast:

```javascript
const { transaction } = await tronWeb.transactionBuilder.triggerSmartContract(
    contractAddress,
    'transfer(address,uint256)',
    { feeLimit: 100_000_000 },
    [
        { type: 'address', value: recipientAddress },
        { type: 'uint256', value: 1_000_000 },
    ],
    signer.address
);
const signed = await tronWeb.trx.signPQ(transaction, signer);
const receipt = await tronWeb.trx.sendRawTransaction(signed);
```

### Network, fees and runtime requirements

- **Scheme activation.** Nile has `FN_DSA_512` active (`getAllowFnDsa512 = 1`); `ML_DSA_44` is not activated on any public TRON network yet. Call `assertSchemeEnabled(tronWeb, scheme)` before building transactions — an inactive scheme is only rejected at broadcast.
- **Bandwidth cost.** PQ signatures are large: a plain `FN_DSA_512` TRX transfer costs ~1763 bandwidth points (serialized size plus the fixed 64-byte result allowance), more than the 600 daily free bandwidth points, so the whole transfer burns TRX for bandwidth — ~1.76 TRX at Nile's 1000 sun/point — unless the account has staked bandwidth. (Reference: `wallet/gettransactioninfobyid` on a plain Falcon transfer on Nile reports `net_fee: 1763000`.)
- **Node.js version.** CommonJS `require('tronweb/pq')` needs a Node.js with `require(ESM)` support — **20.19+ (within v20), 22.12+, or 23+**; other versions fail with `ERR_REQUIRE_ESM` because the underlying `@noble/post-quantum` is ESM-only. ESM `import` is not subject to the `require(ESM)` restriction, but note that `@noble/post-quantum` itself declares `engines: >= 20.19.0`. The main `tronweb` entry is unaffected either way.
- **The wire format is snake_case.** On the wire the fields are `pq_auth_sig`, `public_key`, `signature` — the node **silently drops** camelCase variants (`pqAuthSig`, `publicKey`) instead of erroring. The SDK always emits the correct form; this only matters if you assemble broadcast JSON by hand.

### Not supported

- **Browser `<script>` / CDN builds.** `dist/TronWeb.js` contains no PQ cryptography — key generation, signing and verification are only available from Node.js or a bundler via the `tronweb/pq` subpath.
- **`options.privateKey` on convenience methods.** `trx.sendTrx` / `sendToken` / `freezeBalance` etc. accept only a private-key *string*; PQ private keys are 2176/2560 bytes and do not fit that API. Build the transaction with `transactionBuilder`, then `signPQ` + `sendRawTransaction`, as in the quick start.
- **Message signing.** `signMessage` / `signMessageV2` are ECDSA-only; passing a `TronPQSigner` to `trx.sign(message, ...)` throws — the PQ protocol only covers transaction signatures.
- **Altering a PQ-signed transaction.** `transactionBuilder.alterTransaction` / `extendExpiration` refuse transactions carrying `pq_auth_sig` — changing `raw_data` would change the `txID` and silently invalidate the signature.
- **`ecRecover` on pure-PQ transactions.** Throws, pointing to `Trx.getPQSignerAddresses`.

### Testing

From a clone of this repository (the installed package ships no tests), `npm run test:pq` runs the PQ suite offline — 106 tests, no node required — including byte-level verification of the transactions in `test/fixtures/pq-onchain-transactions.json`: five `FN_DSA_512` and three `ML_DSA_44` transfers that a PQ-enabled java-tron node accepted and executed, signed by throwaway keys derived from trivial seeds (no real account is involved — see `test/pq/onchainFixtures.ts` for their provenance and the seeds).

The same command also runs a node-backed suite, `test/pq/onchain.test.ts`, when pointed at a PQ-enabled node with both schemes active. It signs, broadcasts and confirms real Falcon, ML-DSA and mixed ECDSA + PQ multisig transactions, and checks that the node rejects malformed `pq_auth_sig` entries. It spends funds and installs a permission, so run it against a private network only, never Nile or mainnet:

```bash
PQ_NODE=http://127.0.0.1:16667 PRIVATE_KEY=<funded ECDSA key on that node> npm run test:pq
# add PQ_RECORD_FIXTURES=1 to regenerate test/fixtures/pq-onchain-transactions.json from the run,
# then run `npm run test:pq` again without PQ_NODE: the recording run still loaded the previous fixture
```

Without `PQ_NODE` and `PRIVATE_KEY` that suite is skipped and the run stays offline.

On-chain PQ testing against a public network must target one where the scheme is active — on **Nile** that is `FN_DSA_512`. The local [TRE network](#your-local-private-network-for-heavy-testing) below runs stock java-tron (4.8.2 — its chain parameters carry no `getAllowFnDsa512` / `getAllowMlDsa44` at all), so PQ transactions cannot be tested against it; it remains the right target for the standard `npm test` regression suite. For a PQ-capable private network — the only way to exercise `ML_DSA_44` end to end today, and what the node-backed suite above expects — build java-tron from the PQ tags published at [tron-nile-testnet/nile-testnet](https://github.com/tron-nile-testnet/nile-testnet).

## Your local private network for heavy testing

You can set up a local private TRON network using the **TRON Runtime Environment (TRE)**. This is a Docker-based local blockchain runtime that provides a full TRON network for development, testing, and automation.

To do it you must [install Docker](https://docs.docker.com/install/) and, when ready, run a command like

```bash
docker run -it -p 9090:9090 --rm --name tron tronbox/tre:dev
```

Once running, the local node will be available at: http://localhost:9090

[More details about TRE](https://hub.docker.com/r/tronbox/tre)

> **Note:** the TRE image runs stock java-tron **without** the post-quantum protocol upgrade — use it for the standard test suite, and use [Nile or a PQ-enabled private network](#post-quantum-signatures-nile) for PQ signatures.

## Creating an Instance

First of all, in your typescript file, define TronWeb:

```typescript
import { TronWeb, utils as TronWebUtils, Trx, TransactionBuilder, Contract, Event, Plugin } from 'tronweb';
```

Please note that this is not the same as v5.x. If you want to dive into more differences, check out [migration guide](https://tronweb.network/docu/docs/Migrating%20from%20v5)

When you instantiate TronWeb you can define

* fullNode
* solidityNode
* eventServer
* privateKey

you can also set a

* fullHost

which works as a jolly. If you do so, though, the more precise specification has priority.
Supposing you are using a server which provides everything, like TronGrid, you can instantiate TronWeb as:

```js
const tronWeb = new TronWeb({
    fullHost: 'https://api.trongrid.io',
    headers: { "TRON-PRO-API-KEY": 'your api key' },
    privateKey: 'your private key'
})
```

For retro-compatibility, though, you can continue to use the old approach, where any parameter is passed separately:
```js
const tronWeb = new TronWeb(fullNode, solidityNode, eventServer, privateKey)
tronWeb.setHeader({ "TRON-PRO-API-KEY": 'your api key' });
```

If you are, for example, using a server as full and solidity node, and another server for the events, you can set it as:

```js
const tronWeb = new TronWeb({
    fullHost: 'https://api.trongrid.io',
    eventServer: 'https://api.someotherevent.io',
    privateKey: 'your private key'
  }
)
```

If you are using different servers for anything, you can do
```js
const tronWeb = new TronWeb({
    fullNode: 'https://some-node.tld',
    solidityNode: 'https://some-other-node.tld',
    eventServer: 'https://some-event-server.tld',
    privateKey: 'your private key'
  }
)
```

## FAQ

1. Cannot destructure property 'Transaction' of 'globalThis.TronWebProto' as it is undefined.

This is a problem caused by webpack as it doesn't load cjs file correctly. To solve this problem, you need to add a new rule like below:
```
{
      test: /\.cjs$/,
      type: 'javascript/auto'
}
```

For more questions, please refer to [TronWeb Doc](https://tronweb.network/docu/docs/Migrating%20from%20v5#faq).

## Integrity Check

Upstream signs its npm releases with a GPG key (`dev@tronweb.network`); nothing installed from this fork carries that signature. Verify what you have by provenance instead: a git-ref install is built on your machine from the commit `npm ls tronweb` shows, and a release `.tgz` can be checked against the `shasum` / `integrity` values printed by `npm pack` when it was produced (published alongside the asset), or rebuilt from the tagged commit and compared.

## Contributions

In order to contribute you can

* fork this repo and clone it locally
* install the dependencies — `npm i` (this also runs `prepare`, which builds `lib/` and `dist/`)
* do your changes to the code
* rebuild — `npm run build:all`; to try the clone from another project use `npm install /path/to/clone` or `npm link` (see [Installation](#installation))
* run a local [private network](#your-local-private-network-for-heavy-testing)
* run the tests — `npm run test`
* push your changes and open a pull request

Contact the team at [here](https://developers.tron.network/docs/online-technical-support)


## Licence

TronWeb is distributed under a MIT licence.


