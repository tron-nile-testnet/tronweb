import { TronPQSigner, PQSchemeName } from '../types/PQ.js';
import * as FnDsa512 from './FnDsa512.js';
import * as MlDsa44 from './MlDsa44.js';
import { bytesToHex } from './bytes.js';

export interface CreatePQSignerOptions {
    scheme: PQSchemeName;
    /**
     * Falcon: 48-byte seed, 1280-byte bare key (f‖g‖F) or 2176-byte
     * persisted key (f‖g‖F‖h). ML-DSA: 32-byte seed or 2560-byte key.
     * Auto-detected by length; hex string or bytes. Persist the Falcon
     * private key rather than its seed — see `FnDsa512` on seed stability.
     */
    privateKey: string | Uint8Array;
    /**
     * Optional on-chain public key (hex or bytes) the private key is expected
     * to pair with — the `publicKey` field of java-tron's witness key file,
     * where it is required for Falcon. The public key is always derived from
     * the private key; when this is given it must match, so a file whose two
     * halves were not generated together fails here instead of signing as an
     * account the caller never meant.
     */
    publicKey?: string | Uint8Array;
    /**
     * Optional account address (base58 `T...` or hex `41...`) the key is
     * expected to control — the key file's `address` field. Verified against
     * the address derived from the public key, as the node does.
     */
    address?: string;
}

/**
 * Build a local `TronPQSigner` from key material. The returned object is what
 * `trx.sign()` / `trx.multiSign()` accept in place of a private-key string.
 *
 * The key is validated and the address derived eagerly, so a corrupt or
 * wrong-length key fails here — at construction — rather than at sign time.
 */
export function createPQSigner(options: CreatePQSignerOptions): TronPQSigner {
    const { scheme, privateKey, publicKey, address } = options;
    const impl = scheme === 'FN_DSA_512' ? FnDsa512 : scheme === 'ML_DSA_44' ? MlDsa44 : null;
    if (!impl) {
        throw new Error(`Unsupported PQ scheme: ${String(scheme)}`);
    }
    // A key file may carry only `seed` (the node then runs keygen); this API
    // takes the expanded key, so say so instead of failing on `undefined`.
    if (privateKey == null || (typeof privateKey === 'string' && privateKey.trim() === '')) {
        throw new Error(
            'Invalid PQ signer: privateKey is required; a key file carrying only `seed` is not accepted here — ' +
                'persist and pass the expanded privateKey'
        );
    }
    const keyPair = impl.keyPairFromPrivateKey(privateKey);
    // Mirror the node's key-file checks (java-tron WitnessInitializer): a
    // declared public key or address is verified against what the private
    // key derives, so a misassembled file fails here rather than signing as
    // an account the caller never meant. Blank values count as absent, as
    // the node treats them.
    if (publicKey != null && typeof publicKey !== 'string' && !(publicKey instanceof Uint8Array)) {
        throw new Error('Invalid PQ signer: publicKey must be a hex string or Uint8Array');
    }
    const declaredKey = typeof publicKey === 'string' ? publicKey.trim() : publicKey;
    if (declaredKey != null && declaredKey !== '') {
        const hex = typeof declaredKey === 'string' ? declaredKey.replace(/^0x/i, '').toLowerCase() : bytesToHex(declaredKey);
        if (hex.length !== impl.publicKeySize * 2) {
            const hint =
                scheme === 'FN_DSA_512' && hex.length === (FnDsa512.publicKeySize + 1) * 2
                    ? ' (897 bytes: strip the 1-byte NIST framing header — the on-chain form is the raw 896-byte h)'
                    : '';
            throw new Error(
                `Invalid PQ signer: publicKey must be ${impl.publicKeySize} bytes for ${scheme}, ` +
                    `got ${Math.floor(hex.length / 2)} bytes${hint}`
            );
        }
        if (hex !== keyPair.publicKey) {
            throw new Error(`Invalid PQ signer: publicKey does not match the key derived from privateKey for ${scheme}`);
        }
    }
    if (address != null && typeof address !== 'string') {
        throw new Error('Invalid PQ signer: address must be a base58 or hex string');
    }
    const declaredAddress = typeof address === 'string' ? address.trim() : address;
    if (declaredAddress != null && declaredAddress !== '') {
        const derived = keyPair.address;
        if (declaredAddress !== derived.base58 && declaredAddress.toLowerCase() !== derived.hex) {
            // Do not echo the declared value: a misassembled file may have put
            // key material in this field, and the caller knows what they sent.
            throw new Error(
                `Invalid PQ signer: address does not match the address ${derived.base58} derived from the ${scheme} public key`
            );
        }
    }
    return {
        scheme,
        address: keyPair.address.base58,
        publicKey: keyPair.publicKey,
        signDigest(digest: string): string {
            return impl.sign(digest, keyPair.privateKey);
        },
    };
}
