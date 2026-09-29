/** Small byte/hex helpers local to the PQ modules (browser-safe, no Buffer). */

export function hexToBytes(hex: string): Uint8Array {
    const clean = hex.replace(/^0x/, '').toLowerCase();
    if (clean.length % 2 !== 0 || /[^0-9a-f]/.test(clean)) {
        throw new Error('Invalid hex string');
    }
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
}

export function bytesToHex(bytes: Uint8Array): string {
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
        out += bytes[i].toString(16).padStart(2, '0');
    }
    return out;
}

/**
 * Byte length a hex string would decode to, read off the string without
 * decoding it (fractional for an odd-length string, which never matches a
 * whole-byte expectation). Callers grading untrusted wire data check this
 * before `hexToBytes`, so an oversized string is rejected without first being
 * materialised as bytes.
 */
export function hexByteLength(hex: string): number {
    return hex.replace(/^0x/, '').length / 2;
}

/** Accept hex string or bytes; enforce an exact byte length with a labeled error. */
export function toBytes(value: string | Uint8Array, label: string, ...allowedLengths: number[]): Uint8Array {
    // Validate and length-check the encoded form before decoding: hexToBytes
    // would otherwise allocate for an oversized untrusted string only to have
    // it rejected here. Malformed hex is still named first, as hexToBytes does.
    let length: number;
    if (typeof value === 'string') {
        const clean = value.replace(/^0x/, '');
        if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
            throw new Error('Invalid hex string');
        }
        length = clean.length / 2;
    } else {
        length = value.length;
    }
    if (allowedLengths.length && !allowedLengths.includes(length)) {
        throw new Error(`Invalid ${label} length ${length}; expected ${allowedLengths.join(' or ')} bytes`);
    }
    return typeof value === 'string' ? hexToBytes(value) : value;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
    let offset = 0;
    for (const a of arrays) {
        out.set(a, offset);
        offset += a.length;
    }
    return out;
}

export function randomBytes(length: number): Uint8Array {
    const out = new Uint8Array(length);
    globalThis.crypto.getRandomValues(out);
    return out;
}
