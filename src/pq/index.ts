/**
 * `tronweb/pq` — opt-in post-quantum signature support.
 *
 * This entry point is deliberately separate from the main `tronweb` export so
 * that the PQ crypto implementation (`@noble/post-quantum`) is only loaded by
 * applications that use it; the default bundle is unaffected.
 *
 * The protocol contract backing every byte-level constant in these modules
 * (wire formats, framing, address derivation) is documented where each
 * constant is defined — see the module headers of `FnDsa512.ts` and
 * `MlDsa44.ts` — and verified against real on-chain transactions in
 * `test/pq/` and its fixtures.
 */
import { PQAuthSig, PQSchemeName, PQ_CHAIN_PARAM_KEYS, PQ_MAX_TOTAL_SIGNATURES } from '../types/PQ.js';
import { pqPublicKeyToAddress } from '../utils/crypto.js';
import { cloneTransaction } from '../utils/clone.js';
import { sha256 } from '../utils/ethersUtils.js';
import * as FnDsa512 from './FnDsa512.js';
import * as MlDsa44 from './MlDsa44.js';

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
 * Whether the connected node has the governance proposal for `scheme` active.
 * A missing `value` on the chain parameter means "not activated" (the node
 * omits the key rather than sending 0).
 */
export async function isSchemeEnabled(tronWeb: TronWebLike, scheme: PQSchemeName): Promise<boolean> {
    const params = await tronWeb.trx.getChainParameters();
    const param = params.find((p) => p.key === PQ_CHAIN_PARAM_KEYS[scheme]);
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
            `${scheme} is not activated on this network (chain parameter ${PQ_CHAIN_PARAM_KEYS[scheme]} is unset). ` +
                'The transaction would be rejected at broadcast.'
        );
    }
}

/** The parts of a transaction this module verifies. */
export interface PQVerifiableTransaction {
    txID: string;
    raw_data?: object;
    raw_data_hex?: string;
    pq_auth_sig?: PQAuthSig[];
}

export interface VerifyPQTransactionOptions {
    /**
     * Full payload-binding check, normally `utils.transaction.txCheck` (the
     * top-level `utils` export, or `tronWeb.utils` on an instance).
     * It is injected rather than imported because `utils/transaction.js`
     * imports the whole SDK (protobuf layer included), which would defeat the
     * point of keeping `tronweb/pq` loadable on its own. Supply it whenever
     * the caller acts on `raw_data`: the built-in `raw_data_hex` binding
     * cannot see a decoded `raw_data` JSON that disagrees with the hex, so
     * without `txCheck` such a transaction grades `txIdMatchesPayload: null`,
     * not `true`.
     */
    txCheck?: (transaction: PQVerifiableTransaction) => boolean;
}

export interface PQVerificationResult {
    /**
     * Every entry verifies against `txID` AND the txID is bound to the
     * payload the caller can act on. While a decoded `raw_data` is present
     * this requires `txIdMatchesPayload === true`, so `options.txCheck` must
     * be supplied; without `raw_data`, an uncheckable binding (`null`) does
     * not veto the signatures alone. Signature-only callers read `entries`.
     */
    valid: boolean;
    /**
     * Whether `txID` provably belongs to this transaction's payload. PQ
     * signatures sign the txID and nothing else, so a `valid` verdict is
     * only as trustworthy as this binding. `true`: every payload
     * representation present was checked against `txID` (needs
     * `options.txCheck` when `raw_data` is present). `false`: a check ran
     * and failed — this forces `valid` to false. `null`: some payload could
     * not be checked (typically `raw_data` present without `txCheck`), there
     * was no payload to check at all, or the transaction was refused before
     * grading (`error` is set) and the binding was never evaluated — while
     * `raw_data` is present this also forces `valid` to false.
     */
    txIdMatchesPayload: boolean | null;
    /** Per-entry outcome, in the order the entries appear on the transaction. */
    entries: {
        scheme: string;
        /** 21-byte 0x41-prefixed hex address derived from the embedded public key (convert with TronWeb.address.fromHex). */
        addressHex: string;
        valid: boolean;
        error?: string;
    }[];
    /**
     * Set when the argument itself could not be graded — missing, not an
     * object, or not plain data (a function, class instance, circular
     * reference or throwing accessor inside it) — or carries more than
     * `PQ_MAX_TOTAL_SIGNATURES` `pq_auth_sig` entries, which no node admits
     * even before its ECDSA `signature` entries are counted. `valid` is then
     * false, `entries` is empty and `txIdMatchesPayload` is `null`.
     */
    error?: string;
}

/**
 * Bind `txID` to the payload it claims to describe. PQ signatures sign the
 * txID and nothing else, so without this a transaction whose payload was
 * swapped underneath an intact txID would verify.
 */
function checkTxIdBinding(transaction: PQVerifiableTransaction, options: VerifyPQTransactionOptions): boolean | null {
    if (typeof options.txCheck === 'function') {
        // txCheck re-encodes raw_data and compares both raw_data_hex and the
        // txID digest, so a verdict it actually reaches is definitive.
        try {
            if (options.txCheck(transaction) === true) {
                return true;
            }
            // It ran and disagreed: a genuine disproof.
            return false;
        } catch {
            // It could not run at all — a payload field it dereferences is
            // absent, or the contract type is outside the set it models. That
            // is "unknown", NOT "disproved": grading it `false` would force
            // `valid: false` on a perfectly good transaction and make passing
            // the documented `{ txCheck }` option worse than omitting it. Fall
            // through to the raw_data_hex binding below.
        }
    }
    const rawDataHex = transaction.raw_data_hex;
    if (typeof rawDataHex === 'string' && rawDataHex.length > 0) {
        const clean = rawDataHex.replace(/^0x/, '').toLowerCase();
        if (clean.length % 2 !== 0 || /[^0-9a-f]/.test(clean)) return false;
        if (sha256('0x' + clean).replace(/^0x/, '') !== String(transaction.txID).replace(/^0x/, '').toLowerCase()) {
            return false;
        }
        // The hex matched, but a decoded raw_data JSON riding alongside it is
        // outside what this binding can see — never upgrade that to `true`.
        return transaction.raw_data == null ? true : null;
    }
    return null;
}

/**
 * Locally verify every `pq_auth_sig` entry of a transaction against its txID,
 * and verify that the txID itself belongs to the transaction's payload.
 *
 * Pure offline check — does not consult a node, and does not check that the
 * derived addresses actually hold permission weight on the owner account.
 * Cost is linear in the size of the input: every length check runs on the
 * encoded form before anything is decoded, and a `pq_auth_sig` list longer
 * than `PQ_MAX_TOTAL_SIGNATURES` is refused before any per-entry grading. A
 * caller grading transactions received over the network should still bound
 * the request size upstream, as for any decoder.
 *
 * The payload binding is only as strong as what is available: `raw_data_hex`
 * is checked automatically, while binding the decoded `raw_data` JSON needs
 * `options.txCheck` (pass `utils.transaction.txCheck`, from the top-level
 * `utils` export or `tronWeb.utils` on an instance). `valid` requires a
 * proven binding whenever a decoded `raw_data` is present, is never true
 * when a binding check failed, and `txIdMatchesPayload` reports which of
 * the three states applies.
 *
 * Grades a plain-data snapshot of `transaction`, not the live object, and
 * never throws: an argument that is missing, not an object, or not plain
 * data (functions, class instances, circular references, an accessor that
 * throws) grades `valid: false` with `error` set, as does a `pq_auth_sig`
 * list longer than `PQ_MAX_TOTAL_SIGNATURES`.
 */
export function verifyPQTransaction(
    transaction: PQVerifiableTransaction,
    options: VerifyPQTransactionOptions = {}
): PQVerificationResult {
    // Snapshot first, then read only the snapshot. cloneTransaction reads
    // every property exactly once, so an accessor (getter / Proxy) cannot
    // show one txID to the signature check and another to the payload
    // binding, or one public key to address derivation and another to
    // verify — Trx.getPQSignerAddresses already grades the same way.
    let tx: PQVerifiableTransaction;
    try {
        if (transaction === null || typeof transaction !== 'object') {
            throw new Error('Invalid transaction provided: expected an object');
        }
        tx = cloneTransaction(transaction);
    } catch (err) {
        return { valid: false, txIdMatchesPayload: null, entries: [], error: (err as Error).message };
    }
    // Read each field of the snapshot once and grade from the locals.
    const txID = tx.txID;
    const hasRawData = tx.raw_data != null;
    const list: unknown[] = Array.isArray(tx.pq_auth_sig) ? tx.pq_auth_sig : [];
    // The node counts `signature` and `pq_auth_sig` together against
    // PQ_MAX_TOTAL_SIGNATURES and rejects the whole transaction before looking
    // at any entry, so a pq_auth_sig list longer than that alone is never
    // admitted. Mirror that much — for the same reason: no per-entry grading
    // is spent on such a list. ECDSA `signature` entries are not counted here
    // (this grades PQ signatures, not node admission), so a mixed transaction
    // inside this cap can still exceed the node's.
    if (list.length > PQ_MAX_TOTAL_SIGNATURES) {
        return {
            valid: false,
            txIdMatchesPayload: null,
            entries: [],
            error: `too many pq_auth_sig entries: ${list.length} exceeds the node limit of ${PQ_MAX_TOTAL_SIGNATURES}`,
        };
    }
    // This grades untrusted wire data: never let a malformed entry escape as
    // an exception where the contract promises a { valid: false } verdict.
    const entries: PQVerificationResult['entries'] = list.map((item) => {
        let scheme = 'unknown';
        try {
            const entry = item as Partial<PQAuthSig> | null | undefined;
            scheme = typeof entry?.scheme === 'string' ? entry.scheme : 'unknown';
            const impl = scheme === 'FN_DSA_512' ? FnDsa512 : scheme === 'ML_DSA_44' ? MlDsa44 : null;
            if (!entry || !impl || typeof entry.public_key !== 'string' || typeof entry.signature !== 'string') {
                return { scheme, addressHex: '', valid: false, error: !impl ? 'unknown scheme' : 'malformed entry' };
            }
            const { public_key: publicKey, signature } = entry;
            // Scheme-strict, as the node is: a key of the other scheme's size
            // must not derive an address the node would never credit.
            const addressHex = pqPublicKeyToAddress(publicKey, impl.SCHEME);
            const valid = impl.verify(txID, signature, publicKey);
            return { scheme, addressHex, valid };
        } catch (err) {
            return { scheme, addressHex: '', valid: false, error: (err as Error).message };
        }
    });
    // The node credits each derived address once and rejects a repeat
    // outright ("<addr> has signed twice!"). Grading entries independently
    // would let a caller that sums weights per entry double count a signer,
    // so the repeat is marked invalid — keyed by derived address, as the
    // node does.
    const signed = new Set<string>();
    for (const entry of entries) {
        if (!entry.addressHex) continue;
        if (signed.has(entry.addressHex)) {
            entry.valid = false;
            entry.error = 'duplicate signer: this address already signed';
        } else {
            signed.add(entry.addressHex);
        }
    }
    // Belt and braces: nothing below can throw on plain data, but the
    // contract is a verdict, never an exception.
    let txIdMatchesPayload: boolean | null;
    try {
        txIdMatchesPayload = checkTxIdBinding(tx, options);
    } catch {
        txIdMatchesPayload = null;
    }
    // A decoded raw_data is what a caller renders or acts on, and PQ
    // signatures cannot bind it — only txCheck can. While raw_data is
    // present, an unproven binding must not surface as `valid: true` to a
    // caller that reads only this flag. Without raw_data there is nothing
    // to be misled by, so the signatures alone may grade.
    const payloadBound = hasRawData ? txIdMatchesPayload === true : txIdMatchesPayload !== false;
    return {
        valid: entries.length > 0 && entries.every((e) => e.valid) && payloadBound,
        txIdMatchesPayload,
        entries,
    };
}
