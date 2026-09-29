import { TronPQSigner, PQSchemeName } from '../types/PQ.js';
import * as FnDsa512 from './FnDsa512.js';
import * as MlDsa44 from './MlDsa44.js';

export interface CreatePQSignerOptions {
    scheme: PQSchemeName;
    /**
     * Falcon: 48-byte seed, 1280-byte bare key (f‖g‖F) or 2176-byte
     * persisted key (f‖g‖F‖h). ML-DSA: 32-byte seed or 2560-byte key.
     * Auto-detected by length; hex string or bytes. Persist the Falcon
     * private key rather than its seed — see `FnDsa512` on seed stability.
     */
    privateKey: string | Uint8Array;
}

/**
 * Build a local `TronPQSigner` from key material. The returned object is what
 * `trx.sign()` / `trx.multiSign()` accept in place of a private-key string.
 *
 * The key is validated and the address derived eagerly, so a corrupt or
 * wrong-length key fails here — at construction — rather than at sign time.
 */
export function createPQSigner(options: CreatePQSignerOptions): TronPQSigner {
    const { scheme, privateKey } = options;
    const impl = scheme === 'FN_DSA_512' ? FnDsa512 : scheme === 'ML_DSA_44' ? MlDsa44 : null;
    if (!impl) {
        throw new Error(`Unsupported PQ scheme: ${String(scheme)}`);
    }
    const keyPair = impl.keyPairFromPrivateKey(privateKey);
    return {
        scheme,
        address: keyPair.address.base58,
        publicKey: keyPair.publicKey,
        signDigest(digest: string): string {
            return impl.sign(digest, keyPair.privateKey);
        },
    };
}
