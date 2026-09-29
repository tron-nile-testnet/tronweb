import { describe, it, expect } from 'vitest';
import * as FnDsa512 from '../../src/pq/FnDsa512.js';
import { pqPublicKeyToAddress } from '../../src/utils/crypto.js';
import { sha256 } from '../../src/utils/ethersUtils.js';
import { FIXTURE_FALCON_SEED, falconFixtures } from './onchainFixtures.js';

// Known-answer vectors derived via @noble/post-quantum and validated end-to-end
// against java-tron: the fixtures below are transfers a PQ-enabled node
// accepted from a key derived the same way (see onchainFixtures.ts for their
// provenance — throwaway keys on a local private net, no real account).
// Equivalence with java-tron's BouncyCastle keygen rests on both libraries
// asserting byte-equality against the same round-3 `falcon512-KAT.rsp`
// seed->key vectors; it has not been observed by running BouncyCastle
// directly here.
const KAT_SEED_07 = '07'.repeat(48);
const KAT_ADDRESS_07 = '41b595679a2f6463cc55601c4d837ea9d2cee53982';

describe('FnDsa512 known-answer tests', () => {
    it('derives the KAT address from seed 0x07×48', () => {
        const kp = FnDsa512.keyPairFromSeed(KAT_SEED_07);
        expect(kp.address.hex).toBe(KAT_ADDRESS_07);
        expect(kp.publicKey.length).toBe(FnDsa512.publicKeySize * 2);
        expect(kp.privateKey.length).toBe(FnDsa512.privateKeySize * 2);
        expect(kp.seed).toBe(KAT_SEED_07);
    });

    it('keygen is deterministic', () => {
        const a = FnDsa512.keyPairFromSeed(KAT_SEED_07);
        const b = FnDsa512.keyPairFromSeed(KAT_SEED_07);
        expect(a.publicKey).toBe(b.publicKey);
        expect(a.privateKey).toBe(b.privateKey);
    });

    it('the on-chain fixture owner is exactly the key its trivial seed derives', () => {
        // Closes the loop seed -> key -> address -> accepted by the node: the
        // node derived owner_address from the public key we sent and executed
        // the transfer, so the address derivation matches java-tron's.
        const kp = FnDsa512.keyPairFromSeed(FIXTURE_FALCON_SEED);
        expect(falconFixtures.length).toBeGreaterThan(0);
        for (const f of falconFixtures) {
            expect(f.tx.pq_auth_sig[0].public_key).toBe(kp.publicKey);
            expect(f.tx.raw_data.contract[0].parameter.value.owner_address.toLowerCase()).toBe(kp.address.hex);
        }
    });

    it('round-trips through the 2176-byte persisted private key', () => {
        const original = FnDsa512.keyPairFromSeed(KAT_SEED_07);
        const restored = FnDsa512.keyPairFromPrivateKey(original.privateKey);
        expect(restored.publicKey).toBe(original.publicKey);
        expect(restored.address.base58).toBe(original.address.base58);
        expect(restored.seed).toBeUndefined();
    });

    it('rejects a persisted key whose embedded h does not match f‖g‖F', () => {
        const kp = FnDsa512.keyPairFromSeed(KAT_SEED_07);
        const corrupted = kp.privateKey.slice(0, -2) + (kp.privateKey.endsWith('00') ? '01' : '00');
        expect(() => FnDsa512.keyPairFromPrivateKey(corrupted)).toThrow(/embedded public key/);
    });

    it('rejects F-region corruption at import (h check alone cannot see it)', () => {
        const kp = FnDsa512.keyPairFromSeed(KAT_SEED_07);
        // F block spans bytes 768..1280; flip a bit at byte 900
        const pos = 900 * 2;
        const orig = kp.privateKey.substring(pos, pos + 2);
        const flipped = (parseInt(orig, 16) ^ 0x80).toString(16).padStart(2, '0');
        const corrupted = kp.privateKey.substring(0, pos) + flipped + kp.privateKey.substring(pos + 2);
        expect(() => FnDsa512.keyPairFromPrivateKey(corrupted)).toThrow(/Corrupt FN_DSA_512/);
    });

    it('rejects wrong key and seed lengths with labeled errors', () => {
        expect(() => FnDsa512.keyPairFromSeed('07'.repeat(47))).toThrow(/seed length 47/);
        expect(() => FnDsa512.keyPairFromPrivateKey('ab'.repeat(100))).toThrow(/private key length 100/);
        expect(() => FnDsa512.getAddress('ab'.repeat(897))).toThrow(/public key length 897/);
    });

    it('accepts the bare 1280-byte private key (TIP-899 node key JSON form)', () => {
        // java-tron carries f‖g‖F both bare (1280 B, TIP-899 localPqWitness JSON)
        // and with h appended (2176 B, getPrivateKeyWithPublicKey). Both must import
        // to the same account, and h is recomputed for the bare form.
        const full = FnDsa512.keyPairFromSeed(KAT_SEED_07);
        const bare = full.privateKey.substring(0, FnDsa512.barePrivateKeySize * 2);
        const imported = FnDsa512.keyPairFromPrivateKey(bare);
        expect(imported.publicKey).toBe(full.publicKey);
        expect(imported.address.hex).toBe(KAT_ADDRESS_07);
        expect(imported.privateKey).toBe(full.privateKey); // normalized to the 2176 B form
        // and it can sign directly
        const sig = FnDsa512.sign('ab'.repeat(32), bare);
        expect(FnDsa512.verify('ab'.repeat(32), sig, full.publicKey)).toBe(true);
    });
});

describe('FnDsa512 signing', () => {
    const kp = FnDsa512.keyPairFromSeed(KAT_SEED_07);
    const digest = 'ab'.repeat(32);

    it('produces wire-format signatures within node-enforced bounds', () => {
        for (let i = 0; i < 5; i++) {
            const sig = FnDsa512.sign(digest, kp.privateKey);
            const bytes = sig.length / 2;
            expect(bytes).toBeGreaterThanOrEqual(FnDsa512.signatureMinSize);
            expect(bytes).toBeLessThanOrEqual(FnDsa512.signatureMaxSize);
            expect(sig.substring(0, 2)).toBe('39');
            expect(FnDsa512.verify(digest, sig, kp.publicKey)).toBe(true);
        }
    });

    it('signing is randomized: same digest, different signatures', () => {
        expect(FnDsa512.sign(digest, kp.privateKey)).not.toBe(FnDsa512.sign(digest, kp.privateKey));
    });

    it('signs from a bare seed as well as the persisted key', () => {
        const sig = FnDsa512.sign(digest, KAT_SEED_07);
        expect(FnDsa512.verify(digest, sig, kp.publicKey)).toBe(true);
    });

    it('rejects tampered digests and foreign keys', () => {
        const sig = FnDsa512.sign(digest, kp.privateKey);
        expect(FnDsa512.verify('cd'.repeat(32), sig, kp.publicKey)).toBe(false);
        const other = FnDsa512.keyPairFromSeed('08'.repeat(48));
        expect(FnDsa512.verify(digest, sig, other.publicKey)).toBe(false);
    });

    it('accepts an uppercase 0X prefix on keys, digests and signatures, like 0x', () => {
        const sig = FnDsa512.sign('0X' + digest, kp.privateKey);
        expect(FnDsa512.verify('0X' + digest.toUpperCase(), '0X' + sig, '0X' + kp.publicKey)).toBe(true);
        expect(FnDsa512.getAddress('0X' + kp.publicKey).hex).toBe(kp.address.hex);
        expect(FnDsa512.keyPairFromPrivateKey('0X' + kp.privateKey).address.hex).toBe(kp.address.hex);
    });

    it('rejects malformed signatures without throwing', () => {
        expect(FnDsa512.verify(digest, 'ff'.repeat(650), kp.publicKey)).toBe(false); // wrong header
        expect(FnDsa512.verify(digest, '39' + 'ff'.repeat(100), kp.publicKey)).toBe(false); // too short
        expect(FnDsa512.verify(digest, '39' + 'ff'.repeat(700), kp.publicKey)).toBe(false); // too long
        expect(FnDsa512.verify(digest, '39' + 'ff'.repeat(5_000_000), kp.publicKey)).toBe(false); // oversized: rejected on encoded length
    });

    it('verify() is total — malformed keys and digests return false, never throw', () => {
        const sig = FnDsa512.sign(digest, kp.privateKey);
        expect(FnDsa512.verify(digest, sig, 'ab'.repeat(895))).toBe(false); // wrong pk length
        expect(FnDsa512.verify(digest, sig, 'zz'.repeat(896))).toBe(false); // invalid hex
        expect(FnDsa512.verify('ab'.repeat(31), sig, kp.publicKey)).toBe(false); // wrong digest length
        expect(FnDsa512.verify(digest, 'not-hex', kp.publicKey)).toBe(false);
    });
});

describe('FnDsa512 against transactions accepted by a PQ-enabled java-tron node', () => {
    it('fixture set is non-empty', () => {
        expect(falconFixtures.length).toBeGreaterThanOrEqual(5);
    });

    it.each(falconFixtures.map((f) => [f.block, f] as const))('block %i: verifies on-chain signature', (_block, f) => {
        const entry = f.tx.pq_auth_sig[0];
        expect(entry.scheme).toBe('FN_DSA_512');
        expect(entry.signature.length / 2).toBeGreaterThanOrEqual(FnDsa512.signatureMinSize);
        expect(entry.signature.length / 2).toBeLessThanOrEqual(FnDsa512.signatureMaxSize);
        expect(FnDsa512.verify(f.tx.txID, entry.signature, entry.public_key)).toBe(true);
    });

    it.each(falconFixtures.map((f) => [f.block, f] as const))('block %i: derives owner address from public key', (_block, f) => {
        const derived = pqPublicKeyToAddress(f.tx.pq_auth_sig[0].public_key);
        expect(derived).toBe(f.tx.raw_data.contract[0].parameter.value.owner_address.toLowerCase());
    });

    it.each(falconFixtures.map((f) => [f.block, f] as const))('block %i: txID equals sha256(raw_data_hex)', (_block, f) => {
        expect(sha256('0x' + f.tx.raw_data_hex).replace(/^0x/, '')).toBe(f.tx.txID.toLowerCase());
    });
});
