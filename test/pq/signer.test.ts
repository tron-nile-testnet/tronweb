import { describe, it, expect } from 'vitest';
import { TronWeb } from '../setup/TronWeb.js';
import {
    createPQSigner,
    FnDsa512,
    MlDsa44,
    verifyPQTransaction,
    isTronPQSigner,
    isSchemeEnabled,
    assertSchemeEnabled,
} from '../../src/pq/index.js';
import { attachPQAuthSig, pqPublicKeyToAddress, ECKeySign, pkToAddress } from '../../src/utils/crypto.js';
import { hexStr2byteArray } from '../../src/utils/code.js';
import { txCheck } from '../../src/utils/transaction.js';
import { PQ_MAX_TOTAL_SIGNATURES, PQ_SIGNATURE_HEADERS } from '../../src/types/PQ.js';
import { Trx } from '../../src/lib/trx/trx.js';
import type { PQSignedTransaction, Transaction } from '../../src/types/Transaction.js';
import { FIXTURE_MLDSA_SEED, LOCAL_NODE, falconFixtures, mlDsaFixtures } from './onchainFixtures.js';

const SEED = '07'.repeat(48);

// A Falcon transfer a PQ-enabled java-tron node accepted (throwaway key on a
// local private net, see onchainFixtures.ts) — its raw_data/raw_data_hex/txID
// triple is internally consistent, so it passes txCheck offline. Its owner
// is a different key from SEED, which the single-sign owner check relies on.
const onChainTx = falconFixtures[0].tx;

const cloneTx = () => JSON.parse(JSON.stringify(onChainTx)) as PQSignedTransaction;

describe('createPQSigner', () => {
    it('builds a signer whose address matches the crypto module', () => {
        const kp = FnDsa512.keyPairFromSeed(SEED);
        const signer = createPQSigner({ scheme: 'FN_DSA_512', privateKey: kp.privateKey });
        expect(isTronPQSigner(signer)).toBe(true);
        expect(signer.scheme).toBe('FN_DSA_512');
        expect(signer.address).toBe(kp.address.base58);
        expect(signer.publicKey).toBe(kp.publicKey);
    });

    it('accepts a bare seed and signs verifiable digests', async () => {
        const signer = createPQSigner({ scheme: 'FN_DSA_512', privateKey: SEED });
        const digest = 'ab'.repeat(32);
        const sig = await signer.signDigest(digest);
        expect(FnDsa512.verify(digest, sig, signer.publicKey)).toBe(true);
    });

    it('fails at construction for bad key material and unknown schemes', () => {
        expect(() => createPQSigner({ scheme: 'FN_DSA_512', privateKey: 'ab'.repeat(10) })).toThrow(/length/);
        expect(() => createPQSigner({ scheme: 'NOPE' as never, privateKey: SEED })).toThrow(/Unsupported PQ scheme/);
    });

    it('verifies a declared publicKey and address against the private key, as the node does', () => {
        // The shape of java-tron's localPqWitness key file: the bare 1280-byte
        // f‖g‖F, the 896-byte public key (required there for Falcon) and,
        // optionally, the address. It can be passed as-is.
        const kp = FnDsa512.keyPairFromSeed(SEED);
        const bare = kp.privateKey.slice(0, FnDsa512.barePrivateKeySize * 2);
        const keyFile = { scheme: 'FN_DSA_512' as const, privateKey: bare, publicKey: kp.publicKey, address: kp.address.base58 };
        expect(createPQSigner(keyFile).address).toBe(kp.address.base58);
        // Hex address; 0x-prefixed, uppercase or byte-array public key.
        expect(createPQSigner({ ...keyFile, address: kp.address.hex }).address).toBe(kp.address.base58);
        expect(createPQSigner({ ...keyFile, publicKey: '0x' + kp.publicKey.toUpperCase() }).address).toBe(kp.address.base58);
        expect(createPQSigner({ ...keyFile, publicKey: new Uint8Array(hexStr2byteArray(kp.publicKey)) }).address).toBe(
            kp.address.base58
        );
        // Blank counts as absent, as the node treats it.
        expect(createPQSigner({ ...keyFile, publicKey: '', address: ' ' }).address).toBe(kp.address.base58);
        // Halves from different key pairs are a misassembled file.
        const other = FnDsa512.keyPairFromSeed('08'.repeat(48));
        expect(() => createPQSigner({ ...keyFile, publicKey: other.publicKey })).toThrow(
            /publicKey does not match the key derived from privateKey for FN_DSA_512/
        );
        expect(() => createPQSigner({ ...keyFile, address: other.address.base58 })).toThrow(
            /does not match the address T\w+ derived from the FN_DSA_512 public key/
        );
        expect(() => createPQSigner({ ...keyFile, publicKey: '09' + kp.publicKey })).toThrow(
            /publicKey must be 896 bytes for FN_DSA_512, got 897 bytes \(897 bytes: strip the 1-byte NIST framing header/
        );
        // `0x41…` is the 20-byte EVM form in this codebase, not a TRON hex address.
        expect(() => createPQSigner({ ...keyFile, address: '0x' + kp.address.hex })).toThrow(/does not match the address/);
        // JSON-shaped junk gets a named error, never a bare TypeError.
        expect(() => createPQSigner({ ...keyFile, address: 123 as never })).toThrow(/address must be a base58 or hex string/);
        expect(() => createPQSigner({ ...keyFile, publicKey: 123 as never })).toThrow(/publicKey must be a hex string or Uint8Array/);
        expect(() => createPQSigner({ ...keyFile, privateKey: undefined as never })).toThrow(/privateKey is required/);
        expect(() => createPQSigner({ ...keyFile, privateKey: '  ' })).toThrow(/privateKey is required/);
        // ML-DSA: the node derives the public key; a declared publicKey is optional and verified when given.
        const ml = MlDsa44.keyPairFromSeed('0a'.repeat(32));
        const mlFile = { scheme: 'ML_DSA_44' as const, privateKey: ml.privateKey };
        expect(createPQSigner({ ...mlFile, publicKey: ml.publicKey, address: ml.address.base58 }).address).toBe(ml.address.base58);
        expect(() => createPQSigner({ ...mlFile, publicKey: 'ab'.repeat(1312) })).toThrow(/publicKey does not match/);
        expect(() => createPQSigner({ ...mlFile, publicKey: 'ab'.repeat(1313) })).toThrow(/must be 1312 bytes for ML_DSA_44, got 1313/);
    });
});

describe('attachPQAuthSig', () => {
    const entry = { scheme: 'FN_DSA_512' as const, public_key: 'AB'.repeat(896), signature: '39' + 'cd'.repeat(650) };

    it('creates the array and normalizes hex to bare lowercase', () => {
        const tx = {} as PQSignedTransaction;
        attachPQAuthSig(tx, entry);
        expect(tx.pq_auth_sig).toHaveLength(1);
        expect(tx.pq_auth_sig[0].public_key).toBe('ab'.repeat(896));
        expect(tx.pq_auth_sig[0].signature.startsWith('39')).toBe(true);
    });

    it('dedupes by public key, not by signature bytes (Falcon is randomized)', () => {
        const tx = {} as PQSignedTransaction;
        attachPQAuthSig(tx, entry);
        attachPQAuthSig(tx, { ...entry, signature: '39' + 'ee'.repeat(650) }); // same key, new sig
        expect(tx.pq_auth_sig).toHaveLength(1);
        attachPQAuthSig(tx, { ...entry, public_key: 'ba'.repeat(896) }); // different key
        expect(tx.pq_auth_sig).toHaveLength(2);
    });
});

describe('Trx.sign with a PQ signer', () => {
    // Every test in this file is offline: the instance never issues a request
    // (the node-backed suite is test/pq/onchain.test.ts).
    const tronWeb = new TronWeb({ fullHost: LOCAL_NODE });
    const signer = createPQSigner({ scheme: 'FN_DSA_512', privateKey: SEED });

    it('attaches a verifiable pq_auth_sig entry (multisig path)', async () => {
        const tx = cloneTx();
        const before = tx.pq_auth_sig.length;
        // multisig=true: the fixture owner differs from our test signer
        const signed = await tronWeb.trx.sign(tx as Transaction, signer, true, true);
        expect(signed.pq_auth_sig).toHaveLength(before + 1);
        const added = signed.pq_auth_sig[before];
        expect(added.scheme).toBe('FN_DSA_512');
        expect(added.public_key).toBe(signer.publicKey);
        expect(FnDsa512.verify(signed.txID, added.signature, added.public_key)).toBe(true);
    });

    it('refuses to single-sign a transaction that already carries PQ signatures', async () => {
        await expect(tronWeb.trx.sign(cloneTx() as Transaction, signer)).rejects.toThrow('Transaction is already signed');
    });

    it('enforces the owner-address match for single signing', async () => {
        const tx = cloneTx();
        tx.pq_auth_sig = [];
        await expect(tronWeb.trx.sign(tx as Transaction, signer)).rejects.toThrow(
            'Private key does not match address in transaction'
        );
    });

    it('rejects message signing with a PQ signer', async () => {
        await expect(tronWeb.trx.sign('abcd', signer as never)).rejects.toThrow(/only sign transactions/);
    });

    it('signPQ signs via the dedicated entry point and rejects private-key strings', async () => {
        const tx = cloneTx();
        const before = tx.pq_auth_sig.length;
        const signed = await tronWeb.trx.signPQ(tx as Transaction, signer, true);
        const added = signed.pq_auth_sig[before];
        expect(FnDsa512.verify(signed.txID, added.signature, added.public_key)).toBe(true);
        // a hex private key must never silently fall back to ECDSA here
        await expect(tronWeb.trx.signPQ(cloneTx() as Transaction, 'aa'.repeat(32) as never)).rejects.toThrow(
            /requires a TronPQSigner/
        );
    });

    it('sendRawTransaction accepts a pure-PQ transaction shape and keeps the wire snake_case', async () => {
        // invalid host is never reached because we stub request
        const tx = cloneTx();
        const stub = Object.create(tronWeb.trx) as Trx;
        let posted: unknown;
        (stub as any).tronWeb = {
            fullNode: {
                request: async (_url: string, payload: unknown) => {
                    posted = payload;
                    return { result: true, txid: tx.txID };
                },
            },
        };
        const res = await stub.sendRawTransaction(tx);
        expect(res.result).toBe(true);
        // The node silently DROPS camelCase pqAuthSig/publicKey — a rename
        // anywhere in the pipeline would break broadcasts without an error.
        const wire = JSON.stringify(posted);
        expect(wire).toContain('"pq_auth_sig"');
        expect(wire).toContain('"public_key"');
        expect(wire).not.toContain('pqAuthSig');
        expect(wire).not.toContain('publicKey');
        // and still throws when nothing is attached
        const unsigned = cloneTx();
        unsigned.pq_auth_sig = [];
        await expect(stub.sendRawTransaction(unsigned)).rejects.toThrow('Transaction is not signed');
    });
});

describe('Trx.multiSign with a PQ signer', () => {
    const tronWeb = new TronWeb({ fullHost: LOCAL_NODE });
    const signer = createPQSigner({ scheme: 'FN_DSA_512', privateKey: SEED });

    it('attaches a verifiable entry on the direct path (permissionId 0, no network)', async () => {
        const tx = cloneTx();
        const before = tx.pq_auth_sig.length;
        const signed = await tronWeb.trx.multiSign(tx as Transaction, signer);
        expect(signed.pq_auth_sig).toHaveLength(before + 1);
        const added = signed.pq_auth_sig[before];
        expect(added.public_key).toBe(signer.publicKey);
        expect(FnDsa512.verify(signed.txID, added.signature, added.public_key)).toBe(true);
    });

    it('signing twice with the same PQ signer attaches only one entry', async () => {
        const tx = cloneTx();
        tx.pq_auth_sig = [];
        await tronWeb.trx.multiSign(tx as Transaction, signer);
        const signed = await tronWeb.trx.multiSign(tx as Transaction, signer);
        expect(signed.pq_auth_sig).toHaveLength(1);
    });
});

describe('alterTransaction guard for PQ-signed transactions', () => {
    const tronWeb = new TronWeb({ fullHost: LOCAL_NODE });

    it('extendExpiration rejects a PQ-signed transaction instead of invalidating its signatures', async () => {
        // Pure-PQ tx: pq_auth_sig present, no `signature` key — must hit the
        // same guard that protects ECDSA-signed transactions.
        await expect(tronWeb.transactionBuilder.extendExpiration(cloneTx() as Transaction, 3600)).rejects.toThrow(
            'You can not extend the expiration of a signed transaction.'
        );
    });
});

describe('PQ address recovery and verification', () => {
    it('Trx.getPQSignerAddresses derives the on-chain owner', () => {
        const addresses = Trx.getPQSignerAddresses(cloneTx());
        expect(addresses).toHaveLength(1);
        expect(TronWeb.address.toHex(addresses[0])).toBe(
            onChainTx.raw_data.contract[0].parameter.value.owner_address.toLowerCase()
        );
    });

    it('Trx.ecRecover redirects pure-PQ transactions to getPQSignerAddresses', () => {
        expect(() => Trx.ecRecover(cloneTx() as never)).toThrow(/post-quantum signatures/);
    });

    it('verifyPQTransaction validates all entries of an on-chain tx', () => {
        // The fixture carries a decoded raw_data, so txCheck is what proves
        // the txID binding that a `valid` verdict now requires.
        const result = verifyPQTransaction(cloneTx(), { txCheck });
        expect(result.valid).toBe(true);
        expect(result.txIdMatchesPayload).toBe(true);
        expect(result.entries[0].addressHex).toBe(onChainTx.raw_data.contract[0].parameter.value.owner_address.toLowerCase());
    });

    it('verifyPQTransaction flags a tampered signature', () => {
        const tx = cloneTx();
        const sig = tx.pq_auth_sig[0].signature;
        tx.pq_auth_sig[0].signature = sig.slice(0, -2) + (sig.endsWith('00') ? '01' : '00');
        expect(verifyPQTransaction(tx).valid).toBe(false);
    });

    it('verifyPQTransaction returns valid:false (never throws) on malformed wire data', () => {
        const txID = onChainTx.txID;
        expect(verifyPQTransaction({ txID, pq_auth_sig: [null as never] }).valid).toBe(false);
        expect(verifyPQTransaction({ txID, pq_auth_sig: 'garbage' as never }).valid).toBe(false);
        expect(verifyPQTransaction({ txID, pq_auth_sig: [{ scheme: 'FN_DSA_512' } as never] }).valid).toBe(false);
        expect(verifyPQTransaction({ txID, pq_auth_sig: [] }).valid).toBe(false);
        const short = cloneTx();
        short.pq_auth_sig[0].public_key = 'ab'.repeat(895);
        expect(verifyPQTransaction(short).valid).toBe(false);
    });

    it('attachPQAuthSig tolerates malformed pre-existing co-signer entries', () => {
        const tx = { pq_auth_sig: [{ scheme: 'FN_DSA_512' }] } as never;
        const entry = { scheme: 'FN_DSA_512' as const, public_key: 'ab'.repeat(896), signature: '39' + 'cd'.repeat(650) };
        expect(() => attachPQAuthSig(tx, entry)).not.toThrow();
        expect((tx as { pq_auth_sig: unknown[] }).pq_auth_sig).toHaveLength(2);
    });

    it('pqPublicKeyToAddress rejects odd-length hex instead of dropping the nibble', () => {
        expect(() => pqPublicKeyToAddress(onChainTx.pq_auth_sig[0].public_key + 'a')).toThrow(/not a valid hex/);
    });

    it('pqPublicKeyToAddress names the problem when the key is missing entirely', () => {
        expect(() => pqPublicKeyToAddress(undefined as never)).toThrow(/expected a hex string or Uint8Array/);
        expect(() => pqPublicKeyToAddress(null as never)).toThrow(/expected a hex string or Uint8Array/);
    });

    it('pqPublicKeyToAddress is scheme-strict when a scheme is given', () => {
        const mlKey = 'ab'.repeat(1312);
        expect(pqPublicKeyToAddress(mlKey)).toMatch(/^41/); // scheme-agnostic: any registered size
        expect(pqPublicKeyToAddress(mlKey, 'ML_DSA_44')).toBe(pqPublicKeyToAddress(mlKey));
        expect(() => pqPublicKeyToAddress(mlKey, 'FN_DSA_512')).toThrow(/FN_DSA_512 public key length 1312; expected 896 bytes/);
        expect(() => pqPublicKeyToAddress(mlKey, 'BOGUS' as never)).toThrow(/unknown scheme BOGUS/);
    });

    it("refuses to derive a signer address from a key of the other scheme's size", () => {
        // The node throws "public key or signature length mismatch" for an
        // FN_DSA_512 entry carrying a 1312-byte key; listing an address for
        // it would name a signer the node never credits.
        const tx = cloneTx();
        tx.pq_auth_sig[0].public_key = 'ab'.repeat(1312);
        expect(() => Trx.getPQSignerAddresses(tx)).toThrow(/FN_DSA_512 public key length 1312/);
        const result = verifyPQTransaction(tx, { txCheck });
        expect(result.valid).toBe(false);
        expect(result.entries[0].addressHex).toBe('');
        expect(result.entries[0].error).toMatch(/FN_DSA_512 public key length 1312/);
    });

    it('verifyPQTransaction grades a repeated signer entry invalid, as the node does', () => {
        // The node credits each derived address once and rejects a repeat
        // ("<addr> has signed twice!"); per-entry grading alone would let a
        // caller summing weights double count it.
        const tx = cloneTx();
        tx.pq_auth_sig.push({ ...tx.pq_auth_sig[0] });
        const result = verifyPQTransaction(tx, { txCheck });
        expect(result.valid).toBe(false);
        expect(result.entries.map((e) => e.valid)).toEqual([true, false]);
        expect(result.entries[1].error).toMatch(/duplicate signer/);
    });

    it('verifyPQTransaction refuses more entries than the node admits, before grading any', () => {
        // The node rejects the whole transaction at admission ("total signature
        // count N exceeds 5"); grading 10,000 entries first would spend a full
        // PQ verify on each of them.
        const tx = cloneTx();
        const entry = tx.pq_auth_sig[0];
        tx.pq_auth_sig = Array.from({ length: 10_000 }, () => ({ ...entry }));
        const result = verifyPQTransaction(tx, { txCheck });
        expect(result.valid).toBe(false);
        expect(result.entries).toEqual([]);
        expect(result.error).toMatch(/too many pq_auth_sig entries: 10000 exceeds the node limit of 5/);
        // Exactly the limit is still graded entry by entry.
        tx.pq_auth_sig = Array.from({ length: PQ_MAX_TOTAL_SIGNATURES }, () => ({ ...entry }));
        expect(verifyPQTransaction(tx, { txCheck }).entries).toHaveLength(PQ_MAX_TOTAL_SIGNATURES);
    });

    it('verifyPQTransaction grades oversized wire strings on their encoded length', () => {
        // A 10M-char public_key or signature is rejected from its string
        // length; it is never decoded into bytes first.
        const tx = cloneTx();
        tx.pq_auth_sig[0].public_key = 'ab'.repeat(5_000_000);
        expect(verifyPQTransaction(tx, { txCheck }).entries[0].error).toMatch(
            /FN_DSA_512 public key length 5000000; expected 896 bytes/
        );
        const big = cloneTx();
        big.pq_auth_sig[0].signature = '39' + 'ab'.repeat(5_000_000);
        expect(verifyPQTransaction(big, { txCheck }).entries[0].valid).toBe(false);
    });

    it('ecRecover on a mixed ECDSA+PQ transaction includes the PQ co-signers', () => {
        const tx = cloneTx();
        const ecdsaKey = '11'.repeat(32);
        (tx as never as { signature: string[] }).signature = [ECKeySign(hexStr2byteArray(tx.txID), hexStr2byteArray(ecdsaKey))];
        const recovered = Trx.ecRecover(tx as never) as string[];
        expect(recovered).toHaveLength(2);
        expect(recovered[0]).toBe(pkToAddress(ecdsaKey));
        expect(TronWeb.address.toHex(recovered[1])).toBe(
            onChainTx.raw_data.contract[0].parameter.value.owner_address.toLowerCase()
        );
    });
});

describe('ML_DSA_44 through the signer pipeline', () => {
    // No public network has ML-DSA active yet, so the scheme === 'ML_DSA_44'
    // branches in signer.ts, attachPQAuthSig and verifyPQTransaction are
    // pinned here offline, and their wire format is checked against the
    // ML_DSA_44 transfers a PQ-enabled private net accepted (mlDsaFixtures).
    const tronWeb = new TronWeb({ fullHost: LOCAL_NODE });
    const seed = '09'.repeat(32);
    const signer = createPQSigner({ scheme: 'ML_DSA_44', privateKey: seed });

    it('on-chain ML_DSA_44 fixtures exist', () => {
        expect(mlDsaFixtures.length).toBeGreaterThan(0);
    });

    it.each(mlDsaFixtures.map((f) => [f.block, f] as const))(
        'block %i: an accepted ML_DSA_44 transfer verifies, binds, and derives its owner from the fixture seed',
        (_block, f) => {
            const entry = f.tx.pq_auth_sig[0];
            expect(entry.scheme).toBe('ML_DSA_44');
            expect(entry.public_key.length / 2).toBe(MlDsa44.publicKeySize);
            expect(entry.signature.length / 2).toBe(MlDsa44.signatureSize);
            expect(MlDsa44.verify(f.tx.txID, entry.signature, entry.public_key)).toBe(true);

            const result = verifyPQTransaction(f.tx, { txCheck });
            expect(result.valid).toBe(true);
            expect(result.txIdMatchesPayload).toBe(true);
            const owner = f.tx.raw_data.contract[0].parameter.value.owner_address.toLowerCase();
            expect(result.entries[0].addressHex).toBe(owner);
            expect(TronWeb.address.toHex(Trx.getPQSignerAddresses(f.tx)[0])).toBe(owner);

            const kp = MlDsa44.keyPairFromSeed(FIXTURE_MLDSA_SEED);
            expect(entry.public_key).toBe(kp.publicKey);
            expect(kp.address.hex).toBe(owner);
        }
    );

    const clonePlainTx = () => {
        const tx = cloneTx();
        tx.pq_auth_sig = [];
        return tx;
    };

    it('createPQSigner matches the crypto module for ML_DSA_44', () => {
        const kp = MlDsa44.keyPairFromSeed(seed);
        expect(isTronPQSigner(signer)).toBe(true);
        expect(signer.scheme).toBe('ML_DSA_44');
        expect(signer.address).toBe(kp.address.base58);
        expect(signer.publicKey).toBe(kp.publicKey);
    });

    it('multiSign attaches a verifiable ML_DSA_44 entry on the direct path', async () => {
        const signed = await tronWeb.trx.multiSign(clonePlainTx() as Transaction, signer);
        expect(signed.pq_auth_sig).toHaveLength(1);
        const added = signed.pq_auth_sig[0];
        expect(added.scheme).toBe('ML_DSA_44');
        expect(added.public_key).toBe(signer.publicKey);
        expect(MlDsa44.verify(signed.txID, added.signature, added.public_key)).toBe(true);
    });

    it('signPQ signs with an ML_DSA_44 signer', async () => {
        const signed = await tronWeb.trx.signPQ(clonePlainTx() as Transaction, signer, true);
        expect(MlDsa44.verify(signed.txID, signed.pq_auth_sig[0].signature, signed.pq_auth_sig[0].public_key)).toBe(true);
    });

    it('signing twice with the same ML_DSA_44 signer attaches only one entry', async () => {
        const tx = clonePlainTx();
        await tronWeb.trx.multiSign(tx as Transaction, signer);
        const signed = await tronWeb.trx.multiSign(tx as Transaction, signer);
        expect(signed.pq_auth_sig).toHaveLength(1);
    });

    it('verifyPQTransaction validates the ML_DSA_44 branch and derives its address', async () => {
        const signed = await tronWeb.trx.multiSign(clonePlainTx() as Transaction, signer);
        const result = verifyPQTransaction(signed, { txCheck });
        expect(result.valid).toBe(true);
        expect(result.txIdMatchesPayload).toBe(true);
        expect(result.entries[0].scheme).toBe('ML_DSA_44');
        expect(result.entries[0].addressHex).toBe(MlDsa44.getAddress(signer.publicKey).hex);
    });

    it('a mixed Falcon + ML_DSA_44 transaction verifies and recovers both signers', async () => {
        const signed = await tronWeb.trx.multiSign(cloneTx() as Transaction, signer);
        expect(signed.pq_auth_sig).toHaveLength(2);
        const result = verifyPQTransaction(signed, { txCheck });
        expect(result.valid).toBe(true);
        expect(result.txIdMatchesPayload).toBe(true);
        expect(result.entries.map((e) => e.scheme)).toEqual(['FN_DSA_512', 'ML_DSA_44']);
        const addresses = Trx.getPQSignerAddresses(signed);
        expect(addresses).toHaveLength(2);
        expect(addresses[1]).toBe(signer.address);
    });

    it('sendRawTransaction accepts a pure ML_DSA_44 transaction shape', async () => {
        const signed = await tronWeb.trx.multiSign(clonePlainTx() as Transaction, signer);
        const stub = Object.create(tronWeb.trx) as Trx;
        (stub as any).tronWeb = {
            fullNode: { request: async () => ({ result: true, txid: signed.txID }) },
        };
        const res = await stub.sendRawTransaction(signed);
        expect(res.result).toBe(true);
    });

    it('sendRawTransaction refuses empty signature arrays on both sides', async () => {
        // `signature: []` used to count as signed while `pq_auth_sig: []` did
        // not; the node rejects both as "miss sig or contract".
        const stub = Object.create(tronWeb.trx) as Trx;
        (stub as any).tronWeb = { fullNode: { request: async () => ({ result: true }) } };
        const unsigned = { ...clonePlainTx(), signature: [], pq_auth_sig: [] } as unknown as PQSignedTransaction;
        await expect(stub.sendRawTransaction(unsigned)).rejects.toThrow('Transaction is not signed');
    });
});

describe('isSchemeEnabled / assertSchemeEnabled', () => {
    // The exact shapes wallet/getchainparameters produces: an activated key
    // carries value 1 (sometimes serialized as the string "1" by proxies), a
    // non-activated key is either absent or present without a value.
    const nodeWith = (params: { key: string; value?: number }[]) => ({
        trx: { getChainParameters: async () => params },
    });

    it('true for value 1, both as a number and as a proxy-serialized string', async () => {
        expect(await isSchemeEnabled(nodeWith([{ key: 'getAllowFnDsa512', value: 1 }]), 'FN_DSA_512')).toBe(true);
        expect(await isSchemeEnabled(nodeWith([{ key: 'getAllowFnDsa512', value: '1' as never }]), 'FN_DSA_512')).toBe(true);
    });

    it('false when the key is absent, has no value, or is 0', async () => {
        expect(await isSchemeEnabled(nodeWith([]), 'ML_DSA_44')).toBe(false);
        expect(await isSchemeEnabled(nodeWith([{ key: 'getAllowMlDsa44' }]), 'ML_DSA_44')).toBe(false);
        expect(await isSchemeEnabled(nodeWith([{ key: 'getAllowMlDsa44', value: 0 }]), 'ML_DSA_44')).toBe(false);
        // the other scheme being active must not leak across
        expect(await isSchemeEnabled(nodeWith([{ key: 'getAllowFnDsa512', value: 1 }]), 'ML_DSA_44')).toBe(false);
    });

    it('assertSchemeEnabled resolves when active and names the chain parameter when not', async () => {
        await expect(
            assertSchemeEnabled(nodeWith([{ key: 'getAllowFnDsa512', value: 1 }]), 'FN_DSA_512')
        ).resolves.toBeUndefined();
        await expect(assertSchemeEnabled(nodeWith([]), 'ML_DSA_44')).rejects.toThrow(/getAllowMlDsa44/);
    });
});

describe('verifyPQTransaction payload binding (txIdMatchesPayload)', () => {
    // PQ signatures sign the txID and nothing else: without binding the txID
    // back to the payload, a transaction whose raw_data was swapped underneath
    // an intact txID would still verify.
    it('flags a swapped payload when txCheck is injected', () => {
        const tx = cloneTx();
        (tx.raw_data.contract[0].parameter.value as { amount: number }).amount = 999999999;
        const result = verifyPQTransaction(tx, { txCheck });
        expect(result.txIdMatchesPayload).toBe(false);
        expect(result.valid).toBe(false);
    });

    it('binds the untampered fixture with txCheck', () => {
        const result = verifyPQTransaction(cloneTx(), { txCheck });
        expect(result.txIdMatchesPayload).toBe(true);
        expect(result.valid).toBe(true);
    });

    it('reports null — never true — when raw_data is present but txCheck is not', () => {
        const result = verifyPQTransaction(cloneTx());
        expect(result.txIdMatchesPayload).toBe(null);
        // A decoded raw_data is present and unproven: the signatures alone
        // must not surface as a `valid` the caller would act on.
        expect(result.valid).toBe(false);
        expect(result.entries.every((e) => e.valid)).toBe(true);
    });

    it('binds via raw_data_hex alone when no decoded raw_data rides along', () => {
        const { txID, raw_data_hex, pq_auth_sig } = cloneTx();
        expect(verifyPQTransaction({ txID, raw_data_hex, pq_auth_sig }).txIdMatchesPayload).toBe(true);
        const tampered = raw_data_hex.slice(0, -2) + (raw_data_hex.endsWith('00') ? '01' : '00');
        const result = verifyPQTransaction({ txID, raw_data_hex: tampered, pq_auth_sig });
        expect(result.txIdMatchesPayload).toBe(false);
        expect(result.valid).toBe(false);
    });

    it('reports null with nothing to bind against', () => {
        const { txID, pq_auth_sig } = cloneTx();
        const result = verifyPQTransaction({ txID, pq_auth_sig });
        expect(result.txIdMatchesPayload).toBe(null);
        expect(result.valid).toBe(true);
    });

    // `txCheck` is not a total function: it dereferences raw_data/raw_data_hex
    // and models only part of the contract-type space, so it throws on inputs
    // it cannot re-encode. A throw means "could not check", NOT "check
    // failed" — grading it `false` would force valid:false on a good
    // transaction and make the documented `{ txCheck }` option worse than
    // omitting it.
    it('falls back to the raw_data_hex binding when txCheck cannot run', () => {
        const { txID, raw_data_hex, pq_auth_sig } = cloneTx();
        const result = verifyPQTransaction({ txID, raw_data_hex, pq_auth_sig }, { txCheck });
        expect(result.txIdMatchesPayload).toBe(true);
        expect(result.valid).toBe(true);
    });

    it('grades null when txCheck cannot run and nothing else can bind', () => {
        const { txID, raw_data, pq_auth_sig } = cloneTx();
        const withRawDataOnly = verifyPQTransaction({ txID, raw_data, pq_auth_sig }, { txCheck });
        expect(withRawDataOnly.txIdMatchesPayload).toBe(null);
        expect(withRawDataOnly.valid).toBe(false); // raw_data present, binding unproven

        const withNoPayload = verifyPQTransaction({ txID, pq_auth_sig }, { txCheck });
        expect(withNoPayload.txIdMatchesPayload).toBe(null);
        expect(withNoPayload.valid).toBe(true); // nothing present to be misled by
    });

    it('injecting txCheck is never worse than omitting it', () => {
        const { txID, raw_data, raw_data_hex, pq_auth_sig } = cloneTx();
        const shapes = [
            { txID, raw_data, raw_data_hex, pq_auth_sig },
            { txID, raw_data_hex, pq_auth_sig },
            { txID, raw_data, pq_auth_sig },
            { txID, pq_auth_sig },
        ];
        for (const shape of shapes) {
            const injected = verifyPQTransaction(shape, { txCheck });
            const plain = verifyPQTransaction(shape);
            // These are all genuinely valid transactions: neither call may
            // grade the binding as disproved, every signature verifies, and
            // injecting txCheck can only raise the verdict — it is what
            // proves a raw_data binding.
            expect(injected.txIdMatchesPayload).not.toBe(false);
            expect(plain.txIdMatchesPayload).not.toBe(false);
            expect(injected.entries.every((e) => e.valid)).toBe(true);
            if (plain.valid) expect(injected.valid).toBe(true);
        }
        // With both payload forms present, txCheck is what proves the binding.
        expect(verifyPQTransaction(shapes[0], { txCheck }).valid).toBe(true);
        expect(verifyPQTransaction(shapes[0]).valid).toBe(false);
    });

    it('does not grade valid when tampered raw_data makes txCheck throw', () => {
        // PQ signatures sign the txID only. An attacker who keeps the signed
        // txID/raw_data_hex intact but swaps the decoded raw_data — and adds
        // a field txCheck cannot encode, so it throws instead of disagreeing
        // — must not end up with a `valid: true` a caller would render.
        const tx = cloneTx();
        (tx.raw_data.contract[0].parameter.value as { amount: number }).amount = 999999999;
        (tx.raw_data as { expiration: unknown }).expiration = 'soon';
        expect(() => txCheck(tx)).toThrow();
        const result = verifyPQTransaction(tx, { txCheck });
        expect(result.txIdMatchesPayload).toBe(null);
        expect(result.valid).toBe(false);
        expect(result.entries.every((e) => e.valid)).toBe(true);
    });

    it('still reports false when txCheck runs and genuinely disagrees', () => {
        const tx = cloneTx();
        (tx.raw_data.contract[0].parameter.value as { amount: number }).amount = 999999999;
        const result = verifyPQTransaction(tx, { txCheck });
        expect(result.txIdMatchesPayload).toBe(false);
        expect(result.valid).toBe(false);
    });
});

describe('verifyPQTransaction grades a snapshot of its input', () => {
    // A getter or Proxy could otherwise show one value to the signature check
    // and another to the payload binding or to address derivation. The
    // snapshot reads every property exactly once.
    const throwaway = FnDsa512.keyPairFromSeed('55'.repeat(48));
    const other = FnDsa512.keyPairFromSeed('66'.repeat(48));

    it('reads txID once, so a getter cannot bind the payload to a txID nobody signed', () => {
        const real = cloneTx();
        const decoy = 'bb'.repeat(32);
        const entry = {
            scheme: 'FN_DSA_512' as const,
            public_key: throwaway.publicKey,
            signature: FnDsa512.sign(decoy, throwaway.privateKey),
        };
        let reads = 0;
        const hostile = {
            raw_data: real.raw_data,
            raw_data_hex: real.raw_data_hex,
            pq_auth_sig: [entry],
            get txID() {
                return reads++ === 0 ? decoy : real.txID;
            },
        };
        const result = verifyPQTransaction(hostile as never, { txCheck });
        expect(reads).toBe(1);
        expect(result.valid).toBe(false);
    });

    it('reads public_key once, so addressHex always belongs to the key that verified', () => {
        const digest = cloneTx().txID;
        const signature = FnDsa512.sign(digest, throwaway.privateKey);
        let reads = 0;
        const entry = {
            scheme: 'FN_DSA_512',
            signature,
            get public_key() {
                return reads++ === 0 ? throwaway.publicKey : other.publicKey;
            },
        };
        const result = verifyPQTransaction({ txID: digest, pq_auth_sig: [entry as never] });
        expect(reads).toBe(1);
        expect(result.entries[0].valid).toBe(true);
        expect(result.entries[0].addressHex).toBe(throwaway.address.hex);
        expect(result.valid).toBe(true);
    });

    it('never throws: missing, non-object and non-plain input grade valid:false with an error', () => {
        for (const input of [undefined, null, 'tx', 42]) {
            const result = verifyPQTransaction(input as never);
            expect(result.valid).toBe(false);
            expect(result.entries).toEqual([]);
            expect(result.error).toMatch(/Invalid transaction provided/);
        }
        const txID = cloneTx().txID;
        const withFunction = { txID, pq_auth_sig: [{ scheme: 'FN_DSA_512', public_key: 'ab', signature: 'cd', sign() {} }] };
        expect(verifyPQTransaction(withFunction as never).valid).toBe(false);
        const throwing = {
            txID,
            get pq_auth_sig(): never {
                throw new Error('boom');
            },
        };
        const result = verifyPQTransaction(throwing as never);
        expect(result.valid).toBe(false);
        expect(result.error).toBe('boom');
    });

    it("does not mutate the caller's object", () => {
        const tx = cloneTx();
        const before = JSON.stringify(tx);
        verifyPQTransaction(tx, { txCheck });
        expect(JSON.stringify(tx)).toBe(before);
    });
});

describe('attachPQAuthSig entry validation', () => {
    const good = { scheme: 'FN_DSA_512' as const, public_key: 'ab'.repeat(896), signature: '39' + 'cd'.repeat(650) };

    it('rejects an unknown scheme by name', () => {
        expect(() => attachPQAuthSig({}, { ...good, scheme: 'TOTALLY_BOGUS' as never })).toThrow(/unknown scheme TOTALLY_BOGUS/);
    });

    it('rejects a wrong-length public key, naming the expected size', () => {
        expect(() => attachPQAuthSig({}, { ...good, public_key: 'ab'.repeat(10) })).toThrow(/must be 896 bytes/);
        expect(() =>
            attachPQAuthSig({}, { scheme: 'ML_DSA_44', public_key: 'ab'.repeat(896), signature: good.signature })
        ).toThrow(/must be 1312 bytes/);
    });

    it('points at the NIST framing header for the 897-byte Falcon trap', () => {
        expect(() => attachPQAuthSig({}, { ...good, public_key: '09' + good.public_key })).toThrow(/NIST framing header/);
    });

    it('names a non-hex public key as such, not as a length problem', () => {
        let message = '';
        try {
            attachPQAuthSig({}, { ...good, public_key: 'zz'.repeat(896) });
        } catch (err) {
            message = (err as Error).message;
        }
        expect(message).toMatch(/public_key must be hex/);
        expect(message).not.toMatch(/got 896 bytes/);
    });

    it('strips an uppercase 0X prefix instead of misreading it as the framing header', () => {
        const tx = {} as { pq_auth_sig?: { public_key: string; signature: string }[] };
        attachPQAuthSig(tx, { ...good, public_key: '0X' + good.public_key, signature: '0X' + good.signature });
        expect(tx.pq_auth_sig?.[0].public_key).toBe(good.public_key);
        expect(tx.pq_auth_sig?.[0].signature).toBe(good.signature);
    });

    it('rejects an empty or non-hex signature', () => {
        expect(() => attachPQAuthSig({}, { ...good, signature: '' })).toThrow(/non-empty hex/);
        expect(() => attachPQAuthSig({}, { ...good, signature: 'zz' })).toThrow(/non-empty hex/);
    });

    it('accepts a correct ML_DSA_44 entry', () => {
        const tx = {} as { pq_auth_sig?: unknown[] };
        attachPQAuthSig(tx, { scheme: 'ML_DSA_44', public_key: 'ab'.repeat(1312), signature: 'cd'.repeat(2420) });
        expect(tx.pq_auth_sig).toHaveLength(1);
    });

    // java-tron admits Falcon signatures of 617-667 bytes and ML-DSA-44 of
    // exactly 2420, rejecting the rest at the broadcast gate as an opaque
    // `SIGERROR: pq_auth_sig size is out of bounds`. Name it locally instead.
    it('rejects a signature outside the node-enforced length band', () => {
        expect(() => attachPQAuthSig({}, { ...good, signature: '39' + 'cd'.repeat(600) })).toThrow(
            /FN_DSA_512 signature must be 617-667 bytes, got 601 bytes/
        );
        expect(() => attachPQAuthSig({}, { ...good, signature: '39' + 'cd'.repeat(700) })).toThrow(
            /FN_DSA_512 signature must be 617-667 bytes, got 701 bytes/
        );
        expect(() =>
            attachPQAuthSig({}, { scheme: 'ML_DSA_44', public_key: 'ab'.repeat(1312), signature: 'cd'.repeat(2419) })
        ).toThrow(/ML_DSA_44 signature must be 2420 bytes, got 2419 bytes/);
    });

    it('accepts both ends of the Falcon band', () => {
        for (const size of [617, 667]) {
            const tx = {} as { pq_auth_sig?: unknown[] };
            attachPQAuthSig(tx, { ...good, signature: '39' + 'cd'.repeat(size - 1) });
            expect(tx.pq_auth_sig).toHaveLength(1);
        }
    });

    // The node's verifier returns false for any Falcon header other than
    // 0x39 (FNDSA512.verify), and the TVM precompiles' headerless 666-byte
    // slot sits inside the length band — so the band check alone would let
    // it through to die at broadcast as an opaque `pq sig invalid`.
    it('rejects a Falcon signature whose header byte is not 0x39', () => {
        expect(() => attachPQAuthSig({}, { ...good, signature: '38' + 'cd'.repeat(650) })).toThrow(
            /FN_DSA_512 signature must start with header byte 0x39, got 0x38/
        );
    });

    it('names the headerless TVM-precompile slot when a 666-byte signature lacks the header', () => {
        expect(() => attachPQAuthSig({}, { ...good, signature: 'cd'.repeat(666) })).toThrow(/headerless TVM-precompile slot/);
        // The same length WITH the header is a legitimate transaction signature.
        const tx = {} as { pq_auth_sig?: unknown[] };
        attachPQAuthSig(tx, { ...good, signature: '39' + 'cd'.repeat(665) });
        expect(tx.pq_auth_sig).toHaveLength(1);
    });

    it('the crypto module and the validator share one header constant', () => {
        expect(FnDsa512.signatureHeader).toBe(PQ_SIGNATURE_HEADERS.FN_DSA_512);
        expect(FnDsa512.signatureHeader).toBe(0x39);
    });

    it('a real on-chain signature sits inside the band', () => {
        const entry = onChainTx.pq_auth_sig[0];
        const tx = {} as { pq_auth_sig?: unknown[] };
        attachPQAuthSig(tx, entry);
        expect(tx.pq_auth_sig).toHaveLength(1);
    });
});
