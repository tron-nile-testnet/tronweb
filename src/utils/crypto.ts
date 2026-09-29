import { ADDRESS_PREFIX, ADDRESS_PREFIX_BYTE, ADDRESS_SIZE } from './constants.js';
import { base64EncodeToString, base64DecodeFromString, hexStr2byteArray } from './code.js';
import { encode58, decode58 } from './base58.js';
import { Base64 } from './base64.js';
import { byte2hexStr, byteArray2hexStr } from './bytes.js';
import { keccak256, sha256, recoverAddress, arrayify, Signature } from './ethersUtils.js';
import { secp256k1 as secp } from 'ethereum-cryptography/secp256k1';
import { SignedTransaction } from '../types/Transaction.js';
import { PQAuthSig, PQSchemeName, PQ_PUBLIC_KEY_SIZES, PQ_SIGNATURE_HEADERS, PQ_SIGNATURE_SIZES } from '../types/PQ.js';

import type { BytesLike } from '../types/UtilsTypes.js';

function normalizePrivateKeyBytes(priKeyBytes: BytesLike) {
    return hexStr2byteArray(byteArray2hexStr(priKeyBytes).padStart(64, '0'));
}

export function getBase58CheckAddress(addressBytes: number[]) {
    const hash0 = SHA256(addressBytes);
    const hash1 = SHA256(hash0);

    let checkSum = hash1.slice(0, 4);
    checkSum = addressBytes.concat(checkSum);

    return encode58(checkSum);
}

export function decodeBase58Address(base58Str: string) {
    if (typeof base58Str != 'string') return false;

    if (base58Str.length <= 4) return false;

    let address = decode58(base58Str);

    if (address.length <= 4) return false;

    const len = address.length;
    const offset = len - 4;
    const checkSum = address.slice(offset);

    address = address.slice(0, offset);

    const hash0 = SHA256(address);
    const hash1 = SHA256(hash0);
    const checkSum1 = hash1.slice(0, 4);

    if (
        checkSum[0] === checkSum1[0] &&
        checkSum[1] === checkSum1[1] &&
        checkSum[2] === checkSum1[2] &&
        checkSum[3] === checkSum1[3]
    ) {
        return address;
    }

    throw new Error('Invalid address provided');
}

// @TODO transaction type should be determined.
export function signTransaction(priKeyBytes: string | BytesLike, transaction: any): SignedTransaction {
    if (typeof priKeyBytes === 'string') priKeyBytes = hexStr2byteArray(priKeyBytes);

    const txID = transaction.txID;
    const signature = ECKeySign(hexStr2byteArray(txID), priKeyBytes);

    if (Array.isArray(transaction.signature)) {
        // Signatures coming back from the chain may carry a 0x prefix and differ
        // in hex casing from locally generated ones, so compare normalized values.
        const normalizedSignature = signature.replace(/^0x/, '').toLowerCase();
        const alreadySigned = transaction.signature.some(
            (sig: string) => sig.replace(/^0x/, '').toLowerCase() === normalizedSignature
        );
        if (!alreadySigned) transaction.signature.push(signature);
    } else transaction.signature = [signature];
    return transaction;
}

/**
 * Derive the 21-byte TRON address hex from a PQ public key:
 * `0x41 ‖ Keccak-256(public_key)[12..32]`. The input must already be the
 * on-chain form (896 B for Falcon-512 — framing header stripped; 1312 B for
 * ML-DSA-44); hashing any other length silently yields an unrelated,
 * unspendable address, so the length is enforced here. Pass `scheme` when
 * the key comes with one (a `pq_auth_sig` entry): the node is scheme-strict
 * ("public key or signature length mismatch"), so an FN_DSA_512 entry
 * carrying a 1312-byte key must not derive an address it would never credit.
 */
export function pqPublicKeyToAddress(publicKey: string | Uint8Array, scheme?: PQSchemeName): string {
    // Wire data can arrive with the field missing entirely; a bare TypeError
    // from `bytes.length` below would give the caller nothing to go on.
    if (typeof publicKey !== 'string' && !(publicKey instanceof Uint8Array)) {
        throw new Error('Invalid PQ public key: expected a hex string or Uint8Array');
    }
    let bytes: Uint8Array;
    if (typeof publicKey === 'string') {
        const clean = publicKey.replace(/^0x/i, '');
        // hexStr2byteArray silently drops a dangling nibble; reject instead —
        // deriving an address from malformed hex must fail, not "round down".
        if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
            throw new Error('Invalid PQ public key: not a valid hex string');
        }
        bytes = new Uint8Array(hexStr2byteArray(clean));
    } else {
        bytes = publicKey;
    }
    let valid: number[];
    if (scheme !== undefined) {
        const size = PQ_PUBLIC_KEY_SIZES[scheme];
        if (!size) {
            throw new Error(`Invalid PQ public key: unknown scheme ${String(scheme)}`);
        }
        valid = [size];
    } else {
        valid = Object.values(PQ_PUBLIC_KEY_SIZES);
    }
    if (!valid.includes(bytes.length)) {
        const expected = valid.length > 1 ? `one of ${valid.join(', ')}` : String(valid[0]);
        throw new Error(`Invalid ${scheme ?? 'PQ'} public key length ${bytes.length}; expected ${expected} bytes`);
    }
    const hash = keccak256(bytes).replace(/^0x/, '');
    return ADDRESS_PREFIX + hash.substring(24);
}

/**
 * Attach a PQ signature entry to `transaction.pq_auth_sig`, mirroring what
 * `signTransaction` does for `transaction.signature`. Deduplicates by
 * (scheme, public_key) — NOT by signature bytes: Falcon signing is
 * randomized, so the same key legitimately produces different bytes on every
 * run, and only key identity marks a duplicate signer.
 */
export function attachPQAuthSig<T extends object>(transaction: T, entry: PQAuthSig): T {
    const container = transaction as { pq_auth_sig?: PQAuthSig[] };
    // `createPQSigner` output always passes, but custom signers (hardware
    // wallets, remote signers) are the reason TronPQSigner exists — validate
    // here so their mistakes fail locally with a named cause instead of as an
    // opaque broadcast rejection.
    const expectedKeySize = PQ_PUBLIC_KEY_SIZES[entry?.scheme as keyof typeof PQ_PUBLIC_KEY_SIZES];
    if (!expectedKeySize) {
        throw new Error(
            `Invalid PQ signature entry: unknown scheme ${String(entry?.scheme)}; ` +
                `expected one of ${Object.keys(PQ_PUBLIC_KEY_SIZES).join(', ')}`
        );
    }
    const normalized: PQAuthSig = {
        scheme: entry.scheme,
        // Strip the prefix case-insensitively BEFORE lowercasing: a `0X`
        // that survived would fail the hex test with a length one byte too
        // long and be misreported as the 897-byte framing-header trap.
        public_key: String(entry.public_key ?? '')
            .replace(/^0x/i, '')
            .toLowerCase(),
        signature: String(entry.signature ?? '')
            .replace(/^0x/i, '')
            .toLowerCase(),
    };
    // Content and length are distinct faults; naming the wrong one sends the
    // caller after the wrong fix.
    if (/[^0-9a-f]/.test(normalized.public_key)) {
        throw new Error(`Invalid PQ signature entry: ${entry.scheme} public_key must be hex`);
    }
    if (normalized.public_key.length !== expectedKeySize * 2) {
        const hint =
            entry.scheme === 'FN_DSA_512' && normalized.public_key.length === (expectedKeySize + 1) * 2
                ? ' (897 bytes: strip the 1-byte NIST framing header — the on-chain form is the raw 896-byte h)'
                : '';
        throw new Error(
            `Invalid PQ signature entry: ${entry.scheme} public_key must be ${expectedKeySize} bytes, ` +
                `got ${Math.floor(normalized.public_key.length / 2)} bytes${hint}`
        );
    }
    if (normalized.signature.length === 0 || normalized.signature.length % 2 !== 0 || /[^0-9a-f]/.test(normalized.signature)) {
        throw new Error(`Invalid PQ signature entry: ${entry.scheme} signature must be non-empty hex`);
    }
    // Mirror the node's admission rule exactly (java-tron
    // `PQSchemeRegistry.isValidSignatureLength`, run at the broadcast gate):
    // an out-of-band signature is rejected there as an opaque
    // `SIGERROR: pq_auth_sig size is out of bounds`, so catch it locally with
    // the scheme and the expected band named.
    const band = PQ_SIGNATURE_SIZES[entry.scheme as keyof typeof PQ_SIGNATURE_SIZES];
    const signatureBytes = normalized.signature.length / 2;
    if (signatureBytes < band.min || signatureBytes > band.max) {
        const expected = band.min === band.max ? `${band.min} bytes` : `${band.min}-${band.max} bytes`;
        throw new Error(`Invalid PQ signature entry: ${entry.scheme} signature must be ${expected}, got ${signatureBytes} bytes`);
    }
    // The node's verifier (FNDSA512.verify) returns false for any Falcon
    // header other than 0x39. A headerless TVM-precompile slot is 666 bytes
    // and sits inside the length band, so the band check alone lets it
    // through to die at broadcast as an opaque `SIGERROR: pq sig invalid`.
    const header = (PQ_SIGNATURE_HEADERS as Partial<Record<PQSchemeName, number>>)[entry.scheme];
    if (header !== undefined && parseInt(normalized.signature.slice(0, 2), 16) !== header) {
        const hint =
            signatureBytes === band.max - 1
                ? ' (666 bytes without it looks like the headerless TVM-precompile slot; the transaction form keeps the header)'
                : '';
        throw new Error(
            `Invalid PQ signature entry: ${entry.scheme} signature must start with header byte 0x${header.toString(16)}, ` +
                `got 0x${normalized.signature.slice(0, 2)}${hint}`
        );
    }
    if (Array.isArray(container.pq_auth_sig)) {
        // Existing entries may come from untrusted wire data — guard their
        // shape instead of crashing mid-signing on a malformed co-signer entry.
        const duplicate = container.pq_auth_sig.some(
            (sig) =>
                sig?.scheme === normalized.scheme &&
                typeof sig.public_key === 'string' &&
                sig.public_key.replace(/^0x/, '').toLowerCase() === normalized.public_key
        );
        if (!duplicate) container.pq_auth_sig.push(normalized);
    } else {
        container.pq_auth_sig = [normalized];
    }
    return transaction;
}

export function ecRecover(signedData: string, signature: string) {
    signedData = '0x' + signedData.replace(/^0x/, '');
    signature = '0x' + signature.replace(/^0x/, '');

    const recovered = recoverAddress(arrayify(signedData), Signature.from(signature));
    const tronAddress = ADDRESS_PREFIX + recovered.substring(2);
    return tronAddress;
}

export function arrayToBase64String(a: number[]) {
    return new Base64().encodeIgnoreUtf8(a);
}

export function signBytes(privateKey: string | BytesLike, contents: BytesLike) {
    if (typeof privateKey === 'string') privateKey = hexStr2byteArray(privateKey);

    const hashBytes = SHA256(contents);
    const signBytes = ECKeySign(hashBytes, privateKey);

    return signBytes;
}

export function getRowBytesFromTransactionBase64(base64Data: string): Uint8Array {
    const bytesDecode = base64DecodeFromString(base64Data);
    const { Transaction } = (globalThis as any).TronWebProto;
    const transaction = Transaction.deserializeBinary(bytesDecode);
    const raw = transaction.getRawData();

    return raw.serializeBinary();
}

export function genPriKey() {
    const priKey = secp.utils.randomPrivateKey();
    let priKeyHex = byteArray2hexStr(priKey);

    priKeyHex = priKeyHex.padStart(64, '0');

    return hexStr2byteArray(priKeyHex);
}

export function computeAddress(pubBytes: BytesLike) {
    if (pubBytes.length === 65) pubBytes = pubBytes.slice(1);

    const hash = keccak256(new Uint8Array(pubBytes)).toString().substring(2);
    const addressHex = ADDRESS_PREFIX + hash.substring(24);

    return hexStr2byteArray(addressHex);
}

export function getAddressFromPriKey(priKeyBytes: BytesLike) {
    const pubBytes = getPubKeyFromPriKey(priKeyBytes);
    return computeAddress(pubBytes);
}

export function decode58Check(addressStr: string) {
    const decodeCheck = decode58(addressStr);

    if (decodeCheck.length <= 4) return false;

    const decodeData = decodeCheck.slice(0, decodeCheck.length - 4);
    const hash0 = SHA256(decodeData);
    const hash1 = SHA256(hash0);

    if (
        hash1[0] === decodeCheck[decodeData.length] &&
        hash1[1] === decodeCheck[decodeData.length + 1] &&
        hash1[2] === decodeCheck[decodeData.length + 2] &&
        hash1[3] === decodeCheck[decodeData.length + 3]
    ) {
        return decodeData;
    }

    return false;
}

export function isAddressValid(base58Str: string) {
    if (typeof base58Str !== 'string') return false;

    if (base58Str.length !== ADDRESS_SIZE) return false;

    let address = decode58(base58Str);

    if (address.length !== 25) return false;

    if (address[0] !== ADDRESS_PREFIX_BYTE) return false;

    const checkSum = address.slice(21);
    address = address.slice(0, 21);

    const hash0 = SHA256(address);
    const hash1 = SHA256(hash0);
    const checkSum1 = hash1.slice(0, 4);

    if (
        checkSum[0] == checkSum1[0] &&
        checkSum[1] == checkSum1[1] &&
        checkSum[2] == checkSum1[2] &&
        checkSum[3] == checkSum1[3]
    ) {
        return true;
    }

    return false;
}

export function getBase58CheckAddressFromPriKeyBase64String(priKeyBase64String: string) {
    const priKeyBytes = base64DecodeFromString(priKeyBase64String);
    const pubBytes = getPubKeyFromPriKey(priKeyBytes);
    const addressBytes = computeAddress(pubBytes);

    return getBase58CheckAddress(addressBytes);
}

export function getHexStrAddressFromPriKeyBase64String(priKeyBase64String: string) {
    const priKeyBytes = base64DecodeFromString(priKeyBase64String);
    const pubBytes = getPubKeyFromPriKey(priKeyBytes);
    const addressBytes = computeAddress(pubBytes);
    const addressHex = byteArray2hexStr(addressBytes);

    return addressHex;
}

export function getAddressFromPriKeyBase64String(priKeyBase64String: string) {
    const priKeyBytes = base64DecodeFromString(priKeyBase64String);
    const pubBytes = getPubKeyFromPriKey(priKeyBytes);
    const addressBytes = computeAddress(pubBytes);
    const addressBase64 = base64EncodeToString(addressBytes);

    return addressBase64;
}

export function getPubKeyFromPriKey(priKeyBytes: BytesLike) {
    const pubkey = secp.ProjectivePoint.fromPrivateKey(new Uint8Array(normalizePrivateKeyBytes(priKeyBytes)));
    const x = pubkey.x;
    const y = pubkey.y;

    const xHex = x.toString(16).padStart(64, '0');
    const yHex = y.toString(16).padStart(64, '0');

    const pubkeyHex = `04${xHex}${yHex}`;
    const pubkeyBytes = hexStr2byteArray(pubkeyHex);

    return pubkeyBytes;
}

export function ECKeySign(hashBytes: BytesLike, priKeyBytes: BytesLike) {
    const signature = secp.sign(byteArray2hexStr(hashBytes), byteArray2hexStr(priKeyBytes));

    const r = signature.r.toString(16);
    const s = signature.s.toString(16);
    const v = signature.recovery! + 27;

    return r.padStart(64, '0') + s.padStart(64, '0') + byte2hexStr(v);
}

export function SHA256(msgBytes: BytesLike) {
    const msgHex = byteArray2hexStr(msgBytes);
    const hashHex = sha256('0x' + msgHex).replace(/^0x/, '');
    return hexStr2byteArray(hashHex);
}

export function passwordToAddress(priKeyBase64: string) {
    const com_priKeyBytes = base64DecodeFromString(priKeyBase64);
    const com_addressBytes = getAddressFromPriKey(com_priKeyBytes);

    return getBase58CheckAddress(com_addressBytes);
}

export function pkToAddress(privateKey: string, strict = false) {
    privateKey = privateKey.replace(/^0x/, '');
    const com_priKeyBytes = hexStr2byteArray(privateKey, strict);
    const com_addressBytes = getAddressFromPriKey(com_priKeyBytes);

    return getBase58CheckAddress(com_addressBytes);
}

export function sha3(string: string, prefix = true) {
    return (prefix ? '0x' : '') + keccak256(new TextEncoder().encode(string)).toString().substring(2);
}
