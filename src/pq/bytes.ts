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

/** Accept hex string or bytes; enforce an exact byte length with a labeled error. */
export function toBytes(value: string | Uint8Array, label: string, ...allowedLengths: number[]): Uint8Array {
    const bytes = typeof value === 'string' ? hexToBytes(value) : value;
    if (allowedLengths.length && !allowedLengths.includes(bytes.length)) {
        throw new Error(`Invalid ${label} length ${bytes.length}; expected ${allowedLengths.join(' or ')} bytes`);
    }
    return bytes;
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
