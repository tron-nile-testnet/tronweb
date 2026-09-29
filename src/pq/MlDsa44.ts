/**
 * ML_DSA_44 (ML-DSA-44 / FIPS 204, final) — stateless crypto module.
 *
 * Encodings match FIPS 204 and BouncyCastle exactly, with no framing-byte
 * differences (unlike Falcon): public key = 1312 bytes (ρ‖t1), private key =
 * 2560 bytes (ρ‖K‖tr‖s1‖s2‖t0), signature = fixed 2420 bytes, seed = 32
 * bytes fed to the spec-mandated deterministic KeyGen.
 *
 * Signing MUST go through `ml_dsa44.sign` (the FIPS 204 "pure" mode with an
 * empty context, which prepends the 0x00‖0x00 domain separator) — never
 * `ml_dsa44.internal.sign`, whose output java-tron's MLDSASigner rejects.
 *
 * NOTE: ML_DSA_44 is not yet activated on Nile (`getAllowMlDsa44` unset), so
 * this module is testable locally but transactions signed with it are
 * rejected by the network until the proposal passes.
 */
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { getBase58CheckAddress, pqPublicKeyToAddress } from '../utils/crypto.js';
import { hexStr2byteArray } from '../utils/code.js';
import { bytesToHex, toBytes, randomBytes } from './bytes.js';
import { PQ_SIGNATURE_SIZES } from '../types/PQ.js';

export const SCHEME = 'ML_DSA_44' as const;

export const seedSize = 32;
export const publicKeySize = 1312;
export const privateKeySize = 2560;
export const signatureSize = PQ_SIGNATURE_SIZES.ML_DSA_44.max;

export interface MlDsaKeyPair {
    /** 32-byte seed hex, present only when the key was derived from one. */
    seed?: string;
    /** 2560-byte FIPS 204 private key hex (wallet-cli compatible). */
    privateKey: string;
    /** 1312-byte public key hex. */
    publicKey: string;
    address: {
        base58: string;
        hex: string;
    };
}

function buildKeyPair(publicKey: Uint8Array, secretKey: Uint8Array, seed?: Uint8Array): MlDsaKeyPair {
    const addressHex = pqPublicKeyToAddress(publicKey);
    return {
        ...(seed ? { seed: bytesToHex(seed) } : {}),
        privateKey: bytesToHex(secretKey),
        publicKey: bytesToHex(publicKey),
        address: {
            base58: getBase58CheckAddress(hexStr2byteArray(addressHex)),
            hex: addressHex,
        },
    };
}

/** Generate a key pair from fresh CSPRNG entropy. */
export function generateKeyPair(): MlDsaKeyPair {
    return keyPairFromSeed(randomBytes(seedSize));
}

/**
 * Deterministically derive a key pair from a 32-byte seed (FIPS 204 KeyGen).
 * Integer-only, so unlike Falcon the seed is reproducible across
 * implementations and platforms and is safe to persist on its own.
 */
export function keyPairFromSeed(seed: string | Uint8Array): MlDsaKeyPair {
    const seedBytes = toBytes(seed, 'ML_DSA_44 seed', seedSize);
    const kp = ml_dsa44.keygen(seedBytes);
    return buildKeyPair(kp.publicKey, kp.secretKey, seedBytes);
}

const SELF_TEST_DIGEST = new Uint8Array(32);

/**
 * Import from a 32-byte seed or a 2560-byte private key, detected by length.
 *
 * The 2560-byte path runs a sign/verify self-test: the sk embeds
 * tr = SHAKE256(pk), so a bit-corrupted key that still decodes derives a
 * DIFFERENT address whose signatures never verify — funding that address
 * loses the funds. The self-test rejects exactly those keys at import.
 */
export function keyPairFromPrivateKey(privateKey: string | Uint8Array): MlDsaKeyPair {
    const bytes = toBytes(privateKey, 'ML_DSA_44 private key', seedSize, privateKeySize);
    if (bytes.length === seedSize) return keyPairFromSeed(bytes);
    let publicKey: Uint8Array;
    let consistent = false;
    try {
        publicKey = ml_dsa44.getPublicKey(bytes);
        consistent = ml_dsa44.verify(ml_dsa44.sign(SELF_TEST_DIGEST, bytes), SELF_TEST_DIGEST, publicKey);
    } catch (err) {
        throw new Error(`Corrupt ML_DSA_44 private key: ${(err as Error).message}`);
    }
    if (!consistent) {
        throw new Error('Corrupt ML_DSA_44 private key: embedded tr does not match the derived public key');
    }
    return buildKeyPair(publicKey, bytes);
}

/** Derive the TRON address from a 1312-byte public key. */
export function getAddress(publicKey: string | Uint8Array): { base58: string; hex: string } {
    const bytes = toBytes(publicKey, 'ML_DSA_44 public key', publicKeySize);
    const addressHex = pqPublicKeyToAddress(bytes);
    return {
        base58: getBase58CheckAddress(hexStr2byteArray(addressHex)),
        hex: addressHex,
    };
}

/** Sign a 32-byte digest (the txID) in FIPS 204 pure mode, empty context. */
export function sign(digest: string | Uint8Array, privateKey: string | Uint8Array): string {
    const digestBytes = toBytes(digest, 'digest', 32);
    const keyBytes = toBytes(privateKey, 'ML_DSA_44 private key', seedSize, privateKeySize);
    const secretKey = keyBytes.length === seedSize ? ml_dsa44.keygen(keyBytes).secretKey : keyBytes;
    return bytesToHex(ml_dsa44.sign(digestBytes, secretKey));
}

/**
 * Verify a wire-format signature over a 32-byte digest. Total: malformed
 * inputs of any kind return false rather than throwing, so callers grading
 * untrusted data get a verdict instead of an exception.
 */
export function verify(digest: string | Uint8Array, signature: string | Uint8Array, publicKey: string | Uint8Array): boolean {
    try {
        const digestBytes = toBytes(digest, 'digest', 32);
        // toBytes checks the length on the encoded form before decoding, so an
        // oversized untrusted signature is rejected without being materialised.
        const signatureBytes = toBytes(signature, 'ML_DSA_44 signature', signatureSize);
        const publicKeyBytes = toBytes(publicKey, 'ML_DSA_44 public key', publicKeySize);
        return ml_dsa44.verify(signatureBytes, digestBytes, publicKeyBytes);
    } catch {
        return false;
    }
}
