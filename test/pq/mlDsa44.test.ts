import { describe, it, expect } from 'vitest';
import * as MlDsa44 from '../../src/pq/MlDsa44.js';

const SEED = '09'.repeat(32);

describe('MlDsa44', () => {
    const kp = MlDsa44.keyPairFromSeed(SEED);
    const digest = 'ab'.repeat(32);

    it('produces FIPS 204 sizes (1312/2560/2420, seed 32)', () => {
        expect(kp.publicKey.length).toBe(MlDsa44.publicKeySize * 2);
        expect(kp.privateKey.length).toBe(MlDsa44.privateKeySize * 2);
        const sig = MlDsa44.sign(digest, kp.privateKey);
        expect(sig.length).toBe(MlDsa44.signatureSize * 2);
    });

    it('keygen is deterministic and ρ is shared between pk and sk', () => {
        const again = MlDsa44.keyPairFromSeed(SEED);
        expect(again.publicKey).toBe(kp.publicKey);
        expect(again.privateKey).toBe(kp.privateKey);
        // FIPS 204: pk = ρ‖t1, sk = ρ‖K‖tr‖… — first 32 bytes identical
        expect(kp.publicKey.substring(0, 64)).toBe(kp.privateKey.substring(0, 64));
    });

    it('recovers the public key from the 2560-byte private key', () => {
        const restored = MlDsa44.keyPairFromPrivateKey(kp.privateKey);
        expect(restored.publicKey).toBe(kp.publicKey);
        expect(restored.address.base58).toBe(kp.address.base58);
    });

    it('sign/verify round-trips; wrong digest and foreign key fail', () => {
        const sig = MlDsa44.sign(digest, kp.privateKey);
        expect(MlDsa44.verify(digest, sig, kp.publicKey)).toBe(true);
        expect(MlDsa44.verify('cd'.repeat(32), sig, kp.publicKey)).toBe(false);
        const other = MlDsa44.keyPairFromSeed('0a'.repeat(32));
        expect(MlDsa44.verify(digest, sig, other.publicKey)).toBe(false);
        expect(MlDsa44.verify(digest, 'ff'.repeat(MlDsa44.signatureSize), kp.publicKey)).toBe(false);
        expect(MlDsa44.verify(digest, 'ff'.repeat(100), kp.publicKey)).toBe(false); // wrong length
    });

    it('verify() is total — malformed keys and digests return false, never throw', () => {
        const sig = MlDsa44.sign(digest, kp.privateKey);
        expect(MlDsa44.verify(digest, sig, 'ab'.repeat(1311))).toBe(false); // wrong pk length
        expect(MlDsa44.verify(digest, sig, 'zz'.repeat(1312))).toBe(false); // invalid hex
        expect(MlDsa44.verify('ab'.repeat(31), sig, kp.publicKey)).toBe(false); // wrong digest length
    });

    it('address is 0x41-prefixed 21 bytes derived from the full 1312-byte key', () => {
        expect(kp.address.hex).toMatch(/^41[0-9a-f]{40}$/);
        expect(MlDsa44.getAddress(kp.publicKey).base58).toBe(kp.address.base58);
    });

    it('rejects wrong lengths with labeled errors', () => {
        expect(() => MlDsa44.keyPairFromSeed('09'.repeat(31))).toThrow(/seed length 31/);
        expect(() => MlDsa44.getAddress('ab'.repeat(1311))).toThrow(/public key length 1311/);
    });

    it('rejects bit-corrupted 2560-byte keys at import (would derive an unfundable address)', () => {
        // Corrupt bytes in the s1 packing region; every corruption must throw a
        // labeled error — either noble's decoder rejects it, or the sign/verify
        // self-test catches the tr/pk mismatch. Silent import is the bug.
        for (const bytePos of [150, 200, 300, 450]) {
            const pos = bytePos * 2;
            const orig = kp.privateKey.substring(pos, pos + 2);
            const flipped = (parseInt(orig, 16) ^ 0x01).toString(16).padStart(2, '0');
            const corrupted = kp.privateKey.substring(0, pos) + flipped + kp.privateKey.substring(pos + 2);
            expect(() => MlDsa44.keyPairFromPrivateKey(corrupted)).toThrow(/Corrupt ML_DSA_44/);
        }
    });
});
