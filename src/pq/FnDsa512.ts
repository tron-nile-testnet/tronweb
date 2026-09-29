/**
 * FN_DSA_512 (Falcon-512, Round 3) — stateless crypto module.
 *
 * Wire/interop contract, verified byte-for-byte against java-tron — end to
 * end on Nile, and pinned by the transactions a PQ-enabled node accepted in
 * test/fixtures/pq-onchain-transactions.json:
 *
 * - On-chain public key = 896 bytes: the raw `h`, WITHOUT the 1-byte NIST
 *   framing header. noble keeps the header (897 bytes, pk[0]=0x09); it must
 *   be stripped before hashing or transmitting — hashing 897 bytes derives a
 *   different, unspendable address.
 * - Private key (persisted, wallet-cli compatible) = 2176 bytes: f‖g‖F (1280,
 *   the BouncyCastle getEncoded form) followed by h (896). noble's secret key
 *   is 1281 bytes with a 0x59 header.
 * - Signature = 0x39 ‖ nonce[40] ‖ compressed s2 (variable). The node
 *   enforces total length in [617, 667]; signing retries until it fits.
 * - Seed = 48 bytes, fed directly to SHAKE256 (no DRBG expansion), matching
 *   BouncyCastle's FalconKeyPairGenerator + FixedSecureRandom as used by
 *   wallet-cli. Both libraries assert byte-equality against the same round-3
 *   KAT seed→key vectors, but java-tron marks Falcon keygen (FFT-based) as
 *   NOT bit-stable across platforms and tells operators to persist the
 *   expanded key, never the seed (PQSchemeRegistry.seedDeterministic =
 *   false). Treat the seed as a derivation input: persist `privateKey`.
 */
import { falcon512 } from '@noble/post-quantum/falcon.js';
import { getBase58CheckAddress, pqPublicKeyToAddress } from '../utils/crypto.js';
import { hexStr2byteArray } from '../utils/code.js';
import { hexToBytes, hexByteLength, bytesToHex, toBytes, concatBytes, randomBytes } from './bytes.js';
import { PQ_SIGNATURE_HEADERS, PQ_SIGNATURE_SIZES } from '../types/PQ.js';

export const SCHEME = 'FN_DSA_512' as const;

export const seedSize = 48;
export const publicKeySize = 896;
/** wallet-cli / Toolkit persisted private key: f‖g‖F‖h (java-tron's getPrivateKeyWithPublicKey form). */
export const privateKeySize = 2176;
/**
 * Bare private key f‖g‖F, without the appended public key. This is the form
 * TIP-899's node key JSON carries, so both java-tron representations are
 * accepted on import; `h` is recomputed when it is absent.
 */
export const barePrivateKeySize = 1280;
export const signatureMinSize = PQ_SIGNATURE_SIZES.FN_DSA_512.min;
/** Enforced by the node; noble can rarely exceed it, hence the retry loop. */
export const signatureMaxSize = PQ_SIGNATURE_SIZES.FN_DSA_512.max;
export const signatureHeader = PQ_SIGNATURE_HEADERS.FN_DSA_512;

const NOBLE_PK_HEADER = 0x09; // 0x00 | logn(=9)
const NOBLE_SK_HEADER = 0x59; // 0x50 | logn
const MAX_SIGN_ATTEMPTS = 16;
const SELF_TEST_DIGEST = new Uint8Array(32);

export interface FalconKeyPair {
    /**
     * 48-byte seed hex, present only when the key was derived from one. A
     * derivation input, not a persistence form — persist `privateKey` (see
     * the module header on Falcon seed stability).
     */
    seed?: string;
    /** 2176-byte persisted private key hex (wallet-cli compatible). */
    privateKey: string;
    /** 896-byte on-chain public key hex (framing header stripped). */
    publicKey: string;
    address: {
        base58: string;
        hex: string;
    };
}

function toNoblePublicKey(publicKey896: Uint8Array): Uint8Array {
    return concatBytes(Uint8Array.of(NOBLE_PK_HEADER), publicKey896);
}

function toNobleSecretKey(privateKey2176: Uint8Array): Uint8Array {
    return concatBytes(Uint8Array.of(NOBLE_SK_HEADER), privateKey2176.subarray(0, 1280));
}

function buildKeyPair(noblePk: Uint8Array, nobleSk: Uint8Array, seed?: Uint8Array): FalconKeyPair {
    const publicKey = noblePk.subarray(1);
    const privateKey = concatBytes(nobleSk.subarray(1), publicKey);
    const addressHex = pqPublicKeyToAddress(publicKey);
    return {
        ...(seed ? { seed: bytesToHex(seed) } : {}),
        privateKey: bytesToHex(privateKey),
        publicKey: bytesToHex(publicKey),
        address: {
            base58: getBase58CheckAddress(hexStr2byteArray(addressHex)),
            hex: addressHex,
        },
    };
}

/** Generate a key pair from fresh CSPRNG entropy. */
export function generateKeyPair(): FalconKeyPair {
    return keyPairFromSeed(randomBytes(seedSize));
}

/**
 * Deterministically derive a key pair from a 48-byte seed. Deterministic
 * within this library; whether another implementation reproduces it is not
 * guaranteed (see the module header), so persist the resulting `privateKey`
 * rather than the seed.
 */
export function keyPairFromSeed(seed: string | Uint8Array): FalconKeyPair {
    const seedBytes = toBytes(seed, 'FN_DSA_512 seed', seedSize);
    const kp = falcon512.keygen(seedBytes);
    return buildKeyPair(kp.publicKey, kp.secretKey, seedBytes);
}

/**
 * Import a key pair from a 48-byte seed, a 1280-byte bare private key (f‖g‖F),
 * or a 2176-byte persisted private key (f‖g‖F‖h) — auto-detected by length.
 * All three are forms java-tron / wallet-cli emit.
 */
export function keyPairFromPrivateKey(privateKey: string | Uint8Array): FalconKeyPair {
    const bytes = toBytes(privateKey, 'FN_DSA_512 private key', seedSize, barePrivateKeySize, privateKeySize);
    if (bytes.length === seedSize) return keyPairFromSeed(bytes);
    const nobleSk = toNobleSecretKey(bytes);
    // The bare form omits h, so it is always recomputed. The persisted form
    // carries h alongside f‖g‖F — recompute and compare rather than trust the
    // caller's concatenation.
    const noblePk = falcon512.getPublicKey(nobleSk);
    if (bytes.length === privateKeySize) {
        const embedded = toNoblePublicKey(bytes.subarray(barePrivateKeySize));
        if (bytesToHex(embedded) !== bytesToHex(noblePk)) {
            throw new Error('Corrupt FN_DSA_512 private key: embedded public key does not match f‖g‖F');
        }
    }
    // h depends only on f and g — corruption in the F block passes the check
    // above and would only surface later as a cryptic decode error inside
    // sign(). A one-off test signature moves that failure to import time.
    let consistent = false;
    try {
        consistent = falcon512.verify(falcon512.sign(SELF_TEST_DIGEST, nobleSk), SELF_TEST_DIGEST, noblePk);
    } catch {
        consistent = false;
    }
    if (!consistent) {
        throw new Error('Corrupt FN_DSA_512 private key: self-test signature failed (damaged f‖g‖F encoding)');
    }
    return buildKeyPair(noblePk, nobleSk);
}

/** Derive the TRON address from an on-chain (896-byte) public key. */
export function getAddress(publicKey: string | Uint8Array): { base58: string; hex: string } {
    const bytes = toBytes(publicKey, 'FN_DSA_512 public key', publicKeySize);
    const addressHex = pqPublicKeyToAddress(bytes);
    return {
        base58: getBase58CheckAddress(hexStr2byteArray(addressHex)),
        hex: addressHex,
    };
}

/**
 * Sign a 32-byte digest (the txID). Falcon signing is randomized: repeated
 * calls yield different, equally valid signatures. Retries while the encoding
 * exceeds the node's 667-byte cap (rare — observed 647..662 over thousands of
 * runs — but the theoretical maximum is larger).
 */
export function sign(digest: string | Uint8Array, privateKey: string | Uint8Array): string {
    const digestBytes = toBytes(digest, 'digest', 32);
    const keyBytes = toBytes(privateKey, 'FN_DSA_512 private key', seedSize, barePrivateKeySize, privateKeySize);
    const nobleSk = keyBytes.length === seedSize ? falcon512.keygen(keyBytes).secretKey : toNobleSecretKey(keyBytes);

    for (let attempt = 0; attempt < MAX_SIGN_ATTEMPTS; attempt++) {
        const signature = falcon512.sign(digestBytes, nobleSk);
        if (signature.length <= signatureMaxSize && signature.length >= signatureMinSize) {
            return bytesToHex(signature);
        }
    }
    throw new Error(`FN_DSA_512 signature exceeded ${signatureMaxSize} bytes after ${MAX_SIGN_ATTEMPTS} attempts`);
}

/**
 * Verify a wire-format signature over a 32-byte digest. Total: malformed
 * inputs of any kind return false rather than throwing, so callers grading
 * untrusted data get a verdict instead of an exception.
 */
export function verify(digest: string | Uint8Array, signature: string | Uint8Array, publicKey: string | Uint8Array): boolean {
    try {
        return verifyStrict(digest, signature, publicKey);
    } catch {
        return false;
    }
}

function verifyStrict(digest: string | Uint8Array, signature: string | Uint8Array, publicKey: string | Uint8Array): boolean {
    const digestBytes = toBytes(digest, 'digest', 32);
    // Band-check the signature on its encoded form before decoding: an
    // oversized untrusted string must not be materialised only to be rejected.
    const signatureLength = typeof signature === 'string' ? hexByteLength(signature) : signature.length;
    if (signatureLength < signatureMinSize || signatureLength > signatureMaxSize) {
        return false;
    }
    const signatureBytes = typeof signature === 'string' ? hexToBytes(signature) : signature;
    const publicKeyBytes = toBytes(publicKey, 'FN_DSA_512 public key', publicKeySize);
    if (signatureBytes[0] !== signatureHeader) {
        return false;
    }
    try {
        return falcon512.verify(signatureBytes, digestBytes, toNoblePublicKey(publicKeyBytes));
    } catch {
        return false;
    }
}
