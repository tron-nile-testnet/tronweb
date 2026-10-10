/**
 * Registry through which `Trx.pqRecover` reaches a PQ signature verifier
 * without the main entry importing one. The core bundle must stay free of
 * `@noble/post-quantum` (see `types/PQ.ts`), so the verifiers live in
 * `tronweb/pq`, which registers them here when it is imported — and any
 * application that signs or verifies PQ transactions has imported it
 * already. Until then `getPQVerifier` returns nothing and `pqRecover`
 * refuses, rather than falling back to an unverified derivation.
 */
import type { PQSchemeName } from '../types/PQ.js';

/**
 * `(digest, signature, publicKey) => boolean`, hex in, never throws — the
 * shape of `FnDsa512.verify` and `MlDsa44.verify`.
 */
export type PQVerifier = (digest: string, signature: string, publicKey: string) => boolean;

const verifiers = new Map<PQSchemeName, PQVerifier>();

export function registerPQVerifier(scheme: PQSchemeName, verify: PQVerifier): void {
    verifiers.set(scheme, verify);
}

export function getPQVerifier(scheme: PQSchemeName): PQVerifier | undefined {
    return verifiers.get(scheme);
}
