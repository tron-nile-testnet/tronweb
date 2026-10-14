import { describe, it, expect } from 'vitest';
import { TronWeb } from '../setup/TronWeb.js';
import { createPQSigner, FnDsa512, MlDsa44, isTronPQSigner, isSchemeEnabled, assertSchemeEnabled } from '../../src/pq/index.js';
import { attachPQAuthSig, pqPublicKeyToAddress, ECKeySign, pkToAddress } from '../../src/utils/crypto.js';
import { hexStr2byteArray } from '../../src/utils/code.js';
import { PQ_MAX_TOTAL_SIGNATURES, PQ_SIGNATURE_HEADERS } from '../../src/types/PQ.js';
import { Trx } from '../../src/lib/trx/trx.js';
import type { PQSignedTransaction, Transaction } from '../../src/types/Transaction.js';
import type { TronPQSigner } from '../../src/types/PQ.js';
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
        expect(() => createPQSigner({ ...keyFile, publicKey: 123 as never })).toThrow(
            /publicKey must be a hex string or Uint8Array/
        );
        expect(() => createPQSigner({ ...keyFile, privateKey: undefined as never })).toThrow(/privateKey is required/);
        expect(() => createPQSigner({ ...keyFile, privateKey: '  ' })).toThrow(/privateKey is required/);
        // ML-DSA: the node derives the public key; a declared publicKey is optional and verified when given.
        const ml = MlDsa44.keyPairFromSeed('0a'.repeat(32));
        const mlFile = { scheme: 'ML_DSA_44' as const, privateKey: ml.privateKey };
        expect(createPQSigner({ ...mlFile, publicKey: ml.publicKey, address: ml.address.base58 }).address).toBe(
            ml.address.base58
        );
        expect(() => createPQSigner({ ...mlFile, publicKey: 'ab'.repeat(1312) })).toThrow(/publicKey does not match/);
        expect(() => createPQSigner({ ...mlFile, publicKey: 'ab'.repeat(1313) })).toThrow(
            /must be 1312 bytes for ML_DSA_44, got 1313/
        );
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

    it('dedupes against a pre-existing co-signer entry written with an uppercase 0X prefix', () => {
        // The new entry strips 0X; the existing-entry comparison must too, or
        // the same signer is attached twice and the node rejects the broadcast.
        const tx = { pq_auth_sig: [{ ...entry, public_key: '0X' + entry.public_key }] } as PQSignedTransaction;
        attachPQAuthSig(tx, entry);
        expect(tx.pq_auth_sig).toHaveLength(1);
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

describe('hand-written TronPQSigner validation', () => {
    // A hardware wallet or remote signer implements TronPQSigner by hand, so
    // its scheme / publicKey / address are claims, not derivations. sign and
    // multiSign must read them once, check them against each other before
    // anything is signed, and sign from that snapshot — never from the live
    // object after signDigest resolved.
    const tronWeb = new TronWeb({ fullHost: LOCAL_NODE });
    const local = createPQSigner({ scheme: 'FN_DSA_512', privateKey: SEED });
    const fixtureOwner = TronWeb.address.fromHex(onChainTx.raw_data.contract[0].parameter.value.owner_address);
    const unsignedTx = () => {
        const tx = cloneTx();
        tx.pq_auth_sig = [];
        return tx;
    };
    const counting = (overrides: Partial<TronPQSigner>) => {
        let calls = 0;
        const signer: TronPQSigner = {
            scheme: local.scheme,
            address: local.address,
            publicKey: local.publicKey,
            signDigest(digest: string) {
                calls++;
                return local.signDigest(digest);
            },
            ...overrides,
        };
        return { signer, calls: () => calls };
    };

    it('rejects an address that was not derived from the publicKey, before signing', async () => {
        // Claims the fixture owner's address over SEED's key: the owner check
        // would pass, and the node would reject the signature as the wrong key.
        const { signer, calls } = counting({ address: fixtureOwner });
        await expect(tronWeb.trx.sign(unsignedTx() as Transaction, signer)).rejects.toThrow(
            /Invalid PQ signer: address does not match the address T\w+ derived from the FN_DSA_512 publicKey/
        );
        await expect(tronWeb.trx.multiSign(cloneTx() as Transaction, signer)).rejects.toThrow(/address does not match/);
        expect(calls()).toBe(0);
    });

    it('rejects an unknown scheme and a publicKey of the wrong size, before signing', async () => {
        const unknown = counting({ scheme: 'NOPE' as never });
        await expect(tronWeb.trx.multiSign(cloneTx() as Transaction, unknown.signer)).rejects.toThrow(
            /Invalid PQ signer: unknown scheme NOPE/
        );
        // An ML-DSA-sized key under a Falcon scheme.
        const wrongSize = counting({ publicKey: 'ab'.repeat(1312) });
        await expect(tronWeb.trx.multiSign(cloneTx() as Transaction, wrongSize.signer)).rejects.toThrow(
            /Invalid PQ signer: publicKey must be 896 bytes for FN_DSA_512, got 1312 bytes/
        );
        expect(unknown.calls() + wrongSize.calls()).toBe(0);
    });

    it('signs from the fields read before signDigest, not from what the signer claims afterwards', async () => {
        // A signer that rewrites itself inside signDigest (a reconnecting
        // remote signer, or a hostile one) must not get the rewritten key
        // attached next to a signature made with the original one.
        const other = createPQSigner({ scheme: 'FN_DSA_512', privateKey: '0a'.repeat(48) });
        const signer: TronPQSigner = {
            scheme: local.scheme,
            address: local.address,
            publicKey: local.publicKey,
            signDigest(digest: string) {
                const sig = local.signDigest(digest);
                Object.assign(this as object, { scheme: 'ML_DSA_44', publicKey: other.publicKey, address: other.address });
                return sig;
            },
        };
        const signed = await tronWeb.trx.multiSign(cloneTx() as Transaction, signer);
        const added = signed.pq_auth_sig[signed.pq_auth_sig.length - 1];
        expect(added.scheme).toBe('FN_DSA_512');
        expect(added.public_key).toBe(local.publicKey);
        expect(FnDsa512.verify(signed.txID, added.signature, added.public_key)).toBe(true);
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
    it('Trx.pqRecover verifies the on-chain signature and recovers the owner', () => {
        const addresses = Trx.pqRecover(cloneTx());
        expect(addresses).toHaveLength(1);
        expect(TronWeb.address.toHex(addresses[0])).toBe(
            onChainTx.raw_data.contract[0].parameter.value.owner_address.toLowerCase()
        );
    });

    it("Trx.pqRecover rejects a tampered signature instead of naming its public key's address", () => {
        // Recovery, not derivation: the entry still carries the owner's
        // public key, but the signature no longer verifies against the txID.
        const tx = cloneTx();
        const sig = tx.pq_auth_sig[0].signature;
        tx.pq_auth_sig[0].signature = sig.slice(0, -2) + (sig.endsWith('00') ? '01' : '00');
        expect(() => Trx.pqRecover(tx)).toThrow(/pq_auth_sig\[0\] \(FN_DSA_512\) does not verify/);
    });

    it('Trx.pqRecover refuses more entries than the node admits, before verifying any', () => {
        // The node rejects the whole transaction at admission ("total signature
        // count N exceeds 5"). pqRecover stops at the first entry that fails,
        // but one valid entry repeated fills a list of any length, so without
        // the cap a 10,000-entry list costs 10,000 full PQ verifies on the
        // caller's thread.
        const tx = cloneTx();
        const entry = tx.pq_auth_sig[0];
        // Every entry is tampered: the per-entry check would throw at index 0,
        // so the count error surfacing proves no entry was examined.
        const sig = entry.signature;
        const tampered = { ...entry, signature: sig.slice(0, -2) + (sig.endsWith('00') ? '01' : '00') };
        tx.pq_auth_sig = Array.from({ length: 10_000 }, () => ({ ...tampered }));
        expect(() => Trx.pqRecover(tx)).toThrow(/too many pq_auth_sig entries: 10000 exceeds the node limit of 5/);
        // Exactly the limit is examined entry by entry.
        tx.pq_auth_sig = [{ ...entry }, ...Array.from({ length: PQ_MAX_TOTAL_SIGNATURES - 1 }, () => ({ ...tampered }))];
        expect(() => Trx.pqRecover(tx)).toThrow(/pq_auth_sig\[1\] \(FN_DSA_512\) does not verify/);
    });

    it('Trx.ecRecover redirects pure-PQ transactions to pqRecover', () => {
        expect(() => Trx.ecRecover(cloneTx() as never)).toThrow(/post-quantum signatures/);
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
        expect(() => Trx.pqRecover(tx)).toThrow(/FN_DSA_512 public key length 1312/);
    });

    it('pqRecover refuses oversized wire strings on their encoded length', () => {
        // A 10M-char public_key or signature is rejected from its string
        // length; it is never decoded into bytes first.
        const tx = cloneTx();
        tx.pq_auth_sig[0].public_key = 'ab'.repeat(5_000_000);
        expect(() => Trx.pqRecover(tx)).toThrow(/FN_DSA_512 public key length 5000000; expected 896 bytes/);
        const big = cloneTx();
        big.pq_auth_sig[0].signature = '39' + 'ab'.repeat(5_000_000);
        expect(() => Trx.pqRecover(big)).toThrow(/pq_auth_sig\[0\] \(FN_DSA_512\) does not verify/);
    });

    describe('ecRecover on a mixed ECDSA+PQ transaction', () => {
        // ECDSA recovery is self-authenticating: the address is computed
        // from the signature, so a forged signature yields some other
        // address, never the victim's. A PQ address is derived from the
        // public key that travels next to the signature and is the same
        // whether that signature is genuine or forged, and ecRecover does not
        // verify it. Reporting it beside recovered ECDSA signers would let a
        // tampered pq_auth_sig entry pass as a signer, so ecRecover reports
        // the ECDSA signers only; pqRecover verifies and reports the PQ ones.
        const pqOwner = TronWeb.address.fromHex(onChainTx.raw_data.contract[0].parameter.value.owner_address);
        const ecdsaKeys = ['11'.repeat(32), '22'.repeat(32)];
        const mixed = (keys: string[]) => {
            const tx = cloneTx();
            tx.signature = keys.map((key) => ECKeySign(hexStr2byteArray(tx.txID), hexStr2byteArray(key)));
            return tx;
        };

        it('recovers only the ECDSA signers, shaped by their count as on an ECDSA-only transaction', () => {
            expect(Trx.ecRecover(mixed([ecdsaKeys[0]]) as never)).toBe(pkToAddress(ecdsaKeys[0]));
            expect(Trx.ecRecover(mixed(ecdsaKeys) as never)).toEqual(ecdsaKeys.map((key) => pkToAddress(key)));
        });

        it('never reports a PQ co-signer, whose signature it cannot verify', () => {
            const tx = mixed(ecdsaKeys);
            const sig = tx.pq_auth_sig[0].signature;
            tx.pq_auth_sig[0].signature = sig.slice(0, -2) + (sig.endsWith('00') ? '01' : '00');
            // The forged entry still carries the owner's public key, so a
            // derivation would name the owner as a signer; recovery must not.
            expect(Trx.ecRecover(tx as never)).not.toContain(pqOwner);
            expect(() => Trx.pqRecover(tx)).toThrow(/pq_auth_sig\[0\] \(FN_DSA_512\) does not verify/);
        });

        it('composes with pqRecover into the full, verified signer set', () => {
            const tx = mixed(ecdsaKeys);
            expect([...(Trx.ecRecover(tx as never) as string[]), ...Trx.pqRecover(tx)]).toEqual([
                ...ecdsaKeys.map((key) => pkToAddress(key)),
                pqOwner,
            ]);
        });
    });
});

describe('ML_DSA_44 through the signer pipeline', () => {
    // No public network has ML-DSA active yet, so the scheme === 'ML_DSA_44'
    // branches in signer.ts, attachPQAuthSig and Trx.pqRecover are
    // pinned here offline, and their wire format is checked against the
    // ML_DSA_44 transfers a PQ-enabled private net accepted (mlDsaFixtures).
    const tronWeb = new TronWeb({ fullHost: LOCAL_NODE });
    const seed = '09'.repeat(32);
    const signer = createPQSigner({ scheme: 'ML_DSA_44', privateKey: seed });

    it('on-chain ML_DSA_44 fixtures exist', () => {
        expect(mlDsaFixtures.length).toBeGreaterThan(0);
    });

    it.each(mlDsaFixtures.map((f) => [f.block, f] as const))(
        'block %i: an accepted ML_DSA_44 transfer verifies, recovers, and derives its owner from the fixture seed',
        (_block, f) => {
            const entry = f.tx.pq_auth_sig[0];
            expect(entry.scheme).toBe('ML_DSA_44');
            expect(entry.public_key.length / 2).toBe(MlDsa44.publicKeySize);
            expect(entry.signature.length / 2).toBe(MlDsa44.signatureSize);
            expect(MlDsa44.verify(f.tx.txID, entry.signature, entry.public_key)).toBe(true);

            const owner = f.tx.raw_data.contract[0].parameter.value.owner_address.toLowerCase();
            expect(TronWeb.address.toHex(Trx.pqRecover(f.tx)[0])).toBe(owner);

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

    it('pqRecover recovers the ML_DSA_44 signer of a freshly signed transaction', async () => {
        const signed = await tronWeb.trx.multiSign(clonePlainTx() as Transaction, signer);
        expect(signed.pq_auth_sig[0].scheme).toBe('ML_DSA_44');
        expect(Trx.pqRecover(signed)).toEqual([MlDsa44.getAddress(signer.publicKey).base58]);
    });

    it('a mixed Falcon + ML_DSA_44 transaction verifies and recovers both signers', async () => {
        const signed = await tronWeb.trx.multiSign(cloneTx() as Transaction, signer);
        expect(signed.pq_auth_sig.map((e) => e.scheme)).toEqual(['FN_DSA_512', 'ML_DSA_44']);
        const addresses = Trx.pqRecover(signed);
        expect(addresses).toHaveLength(2);
        expect(addresses[1]).toBe(signer.address);
        // Each entry is verified with its own scheme: a tampered ML-DSA
        // signature fails as ML-DSA, and names its position.
        const sig = signed.pq_auth_sig[1].signature;
        signed.pq_auth_sig[1].signature = sig.slice(0, -2) + (sig.endsWith('00') ? '01' : '00');
        expect(() => Trx.pqRecover(signed)).toThrow(/pq_auth_sig\[1\] \(ML_DSA_44\) does not verify/);
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

describe('Trx.pqRecover binds the txID to the payload', () => {
    // PQ signatures sign the txID and nothing else: without binding the txID
    // back to the payload, a transaction whose raw_data was swapped underneath
    // an intact, correctly signed txID would still name its signer.
    it('refuses a swapped decoded raw_data', () => {
        const tx = cloneTx();
        (tx.raw_data.contract[0].parameter.value as { amount: number }).amount = 999999999;
        expect(() => Trx.pqRecover(tx)).toThrow('Invalid transaction');
    });

    it('refuses a tampered raw_data_hex', () => {
        const tx = cloneTx();
        tx.raw_data_hex = tx.raw_data_hex.slice(0, -2) + (tx.raw_data_hex.endsWith('00') ? '01' : '00');
        expect(() => Trx.pqRecover(tx)).toThrow('Invalid transaction');
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
