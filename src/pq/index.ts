/**
 * `tronweb/pq` — post-quantum signature support: key generation, signing,
 * `createPQSigner` and scheme activation checks.
 *
 * Signature verification itself is also wired into the main entry —
 * `Trx.pqRecover` reaches `FnDsa512.verify` / `MlDsa44.verify` through the
 * fixed table in `utils/pqVerifier.ts` — so `tronweb` depends on
 * `@noble/post-quantum` whether or not this module is imported. This entry
 * point groups the rest of the PQ surface so that it stays out of the main
 * export's namespace; it is not a loading boundary for the crypto.
 *
 * The protocol contract backing every byte-level constant in these modules
 * (wire formats, framing, address derivation) is documented where each
 * constant is defined — see the module headers of `FnDsa512.ts` and
 * `MlDsa44.ts` — and verified against real on-chain transactions in
 * `test/pq/` and its fixtures.
 */
import { PQSchemeName, PQ_CHAIN_PARAM_KEYS } from '../types/PQ.js';

export * as FnDsa512 from './FnDsa512.js';
export * as MlDsa44 from './MlDsa44.js';
export { createPQSigner } from './signer.js';
export type { CreatePQSignerOptions } from './signer.js';
export type { PQAuthSig, PQSchemeName, TronPQSigner } from '../types/PQ.js';
export { PQ_CHAIN_PARAM_KEYS, PQ_MAX_TOTAL_SIGNATURES, PQ_PUBLIC_KEY_SIZES, isTronPQSigner } from '../types/PQ.js';

/** Minimal structural view of TronWeb used here, to avoid a circular import. */
interface TronWebLike {
    trx: {
        getChainParameters(): Promise<{ key: string; value?: number }[]>;
    };
}

/**
 * The chain parameter gating `scheme`, or a named error for a scheme this
 * build does not know. Checked before any network call: `scheme` is typed,
 * but a JS caller or a typo (`'FN-DSA-512'`) gets here unchecked, and an
 * unknown name must not read as "not activated on this network" — nor name
 * its chain parameter as `undefined`. Own-property check, so an inherited
 * `Object.prototype` name (`toString`) does not pass as a scheme either.
 */
function chainParamKeyFor(scheme: PQSchemeName): string {
    if (!Object.prototype.hasOwnProperty.call(PQ_CHAIN_PARAM_KEYS, scheme)) {
        throw new Error(
            `Unsupported PQ scheme: ${String(scheme)}; expected one of ${Object.keys(PQ_CHAIN_PARAM_KEYS).join(', ')}`
        );
    }
    return PQ_CHAIN_PARAM_KEYS[scheme];
}

/**
 * Whether the connected node has the governance proposal for `scheme` active.
 * A missing `value` on the chain parameter means "not activated" (the node
 * omits the key rather than sending 0).
 */
export async function isSchemeEnabled(tronWeb: TronWebLike, scheme: PQSchemeName): Promise<boolean> {
    const key = chainParamKeyFor(scheme);
    const params = await tronWeb.trx.getChainParameters();
    const param = params.find((p) => p.key === key);
    // Compare stringified: `trx.raw` and some proxies serialize int64 chain
    // parameters as JSON strings, where a strict `=== 1` would false-negative.
    return String(param?.value ?? '0') === '1';
}

/**
 * Throw unless `scheme` is activated on the connected network. Call this at
 * account-construction time so an unusable scheme fails early and legibly,
 * instead of surfacing as a broadcast rejection.
 */
export async function assertSchemeEnabled(tronWeb: TronWebLike, scheme: PQSchemeName): Promise<void> {
    if (!(await isSchemeEnabled(tronWeb, scheme))) {
        throw new Error(
            `${scheme} is not activated on this network (chain parameter ${chainParamKeyFor(scheme)} is unset). ` +
                'The transaction would be rejected at broadcast.'
        );
    }
}
