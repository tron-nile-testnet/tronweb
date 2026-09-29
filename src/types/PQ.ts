/**
 * Post-quantum (PQ) signature types shared by the core SDK and the opt-in
 * `tronweb/pq` entry point. This module is type-only plus small constants —
 * it must never import the PQ crypto implementation, so that the default
 * bundle stays free of `@noble/post-quantum`.
 */

/**
 * On-chain PQ signature schemes. Values are the exact enum names emitted and
 * accepted by java-tron's HTTP API (`PQScheme` proto enum) — matching is
 * case-sensitive on the node side.
 */
export type PQSchemeName = 'FN_DSA_512' | 'ML_DSA_44';

/**
 * One entry of `Transaction.pq_auth_sig`, exactly as it travels on the wire.
 *
 * Field names are snake_case on purpose: the node's JSON parser silently
 * drops camelCase variants (`pqAuthSig`, `publicKey`) without an error, so
 * this interface doubles as the serialization format.
 *
 * - `public_key`: lowercase hex, no 0x. 896 bytes (Falcon-512, header
 *   stripped) or 1312 bytes (ML-DSA-44).
 * - `signature`: lowercase hex. Falcon: variable 617–667 bytes, first byte
 *   0x39. ML-DSA: fixed 2420 bytes.
 */
export interface PQAuthSig {
    scheme: PQSchemeName;
    public_key: string;
    signature: string;
}

/**
 * Scheme-agnostic signer handed to `Trx.sign()` / `Trx.multiSign()` in place
 * of a raw private-key string. PQ private keys are 2176/2560 bytes, so the
 * hex-string-threading API cannot carry them; the signer object also lets
 * hardware wallets and remote signers plug in without touching key material.
 */
export interface TronPQSigner {
    readonly scheme: PQSchemeName;
    /** Base58check address (T...) derived from the public key. */
    readonly address: string;
    /** On-chain form public key, lowercase hex (Falcon header already stripped). */
    readonly publicKey: string;
    /**
     * Sign a 32-byte digest (the transaction's txID) and return the
     * wire-format signature as hex. The digest is signed as-is — no re-hash,
     * no context string.
     */
    signDigest(digest: string): Promise<string> | string;
}

/** Runtime guard distinguishing a signer object from a private-key string. */
export function isTronPQSigner(value: unknown): value is TronPQSigner {
    return (
        typeof value === 'object' &&
        value !== null &&
        typeof (value as TronPQSigner).signDigest === 'function' &&
        typeof (value as TronPQSigner).scheme === 'string'
    );
}

/** Chain parameter keys gating each scheme (wallet/getchainparameters). */
export const PQ_CHAIN_PARAM_KEYS: Record<PQSchemeName, string> = {
    FN_DSA_512: 'getAllowFnDsa512',
    ML_DSA_44: 'getAllowMlDsa44',
};

/** Expected on-chain public key byte length per scheme. */
export const PQ_PUBLIC_KEY_SIZES: Record<PQSchemeName, number> = {
    FN_DSA_512: 896,
    ML_DSA_44: 1312,
};

/**
 * Accepted signature byte-length band per scheme, mirroring java-tron's
 * admission rule (`PQSchemeRegistry.isValidSignatureLength`, enforced at the
 * broadcast gate by `Wallet.broadcastTransaction` via
 * `PQAuthSigValidator.isLengthWithinBounds`). Fixed-length schemes degenerate
 * to `min === max`. Falcon signatures are variable-length, so the band — not a
 * single size — is the contract.
 */
export const PQ_SIGNATURE_SIZES: Record<PQSchemeName, { min: number; max: number }> = {
    FN_DSA_512: { min: 617, max: 667 },
    ML_DSA_44: { min: 2420, max: 2420 },
};

/**
 * Leading byte a scheme's transaction signature must carry, where one
 * exists. Falcon's compressed encoding is 0x39 (0x30 | logn, logn = 9);
 * java-tron's `FNDSA512.verify` returns false for any other header (the
 * padded 0x49 and constant-time 0x59 forms), and the TVM precompiles use a
 * separate headerless 666-byte slot — so the header is part of the
 * transaction wire contract. ML-DSA signatures have no header.
 */
export const PQ_SIGNATURE_HEADERS = { FN_DSA_512: 0x39 } as const satisfies Partial<Record<PQSchemeName, number>>;
