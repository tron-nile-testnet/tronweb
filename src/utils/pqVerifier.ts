/**
 * The PQ signature verifiers `Trx.pqRecover` uses: a fixed table, one entry
 * per supported scheme, bound when this module loads.
 *
 * A table and not a registry, on purpose. An earlier design had `tronweb/pq`
 * register the verifiers as an import side effect so that the main entry
 * would not import the PQ crypto. That tied the lookup to module identity:
 * in an ESM/CJS dual-package install, `require('tronweb')` and
 * `import 'tronweb/pq'` (or the reverse) resolve to separate copies under
 * `lib/commonjs` and `lib/esm`, so the registration landed in one copy, the
 * lookup ran in the other, and `pqRecover` reported a missing import that had
 * in fact happened. A table bound here has no state to miss: every copy of
 * `tronweb` carries its own verifiers, whichever loader brought it in.
 *
 * The price is that the main entry depends on `@noble/post-quantum`, which is
 * ESM-only, so `require('tronweb')` needs a Node.js with `require(esm)`
 * (20.19+ / 22.12+ / 23+), as `require('tronweb/pq')` already did. Key
 * generation and signing stay in `tronweb/pq`. `types/PQ.ts` must still not
 * import the crypto: the scheme modules take their constants from it.
 */
import type { PQSchemeName } from '../types/PQ.js';
import * as FnDsa512 from '../pq/FnDsa512.js';
import * as MlDsa44 from '../pq/MlDsa44.js';

/**
 * `(digest, signature, publicKey) => boolean`, hex in, never throws — the
 * shape of `FnDsa512.verify` and `MlDsa44.verify`.
 */
export type PQVerifier = (digest: string, signature: string, publicKey: string) => boolean;

/** One verifier per supported scheme. Frozen: nothing registers into it. */
export const PQ_VERIFIERS: Readonly<Record<PQSchemeName, PQVerifier>> = Object.freeze({
    FN_DSA_512: FnDsa512.verify,
    ML_DSA_44: MlDsa44.verify,
});

/**
 * The verifier for `scheme`, or undefined for any other string. The scheme
 * is wire data, so this is an own-property lookup: an inherited name such as
 * `constructor` must not come back as a callable "verifier".
 */
export function getPQVerifier(scheme: string): PQVerifier | undefined {
    if (!Object.prototype.hasOwnProperty.call(PQ_VERIFIERS, scheme)) return undefined;
    return PQ_VERIFIERS[scheme as PQSchemeName];
}
