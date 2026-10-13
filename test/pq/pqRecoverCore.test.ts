import { describe, it, expect } from 'vitest';
import { Trx } from '../../src/lib/trx/trx.js';
import { PQ_MAX_TOTAL_SIGNATURES } from '../../src/types/PQ.js';
import { falconFixtures } from './onchainFixtures.js';

// This file deliberately never imports `src/pq` — it exercises the main entry
// on its own, the way an application that loaded only `tronweb` would (and
// the way the CDN bundle always is). The core carries no PQ verifier of its
// own, so pqRecover must refuse here rather than fall back to deriving an
// address from the public key, which would name a signer it never checked.
// (vitest isolates each test file's module graph, so the registration that
// `tronweb/pq` performs in the other PQ test files does not leak in.)
describe('Trx.pqRecover without tronweb/pq loaded', () => {
    const tx = JSON.parse(JSON.stringify(falconFixtures[0].tx));

    it('refuses to recover, pointing at tronweb/pq, instead of deriving unverified addresses', () => {
        expect(() => Trx.pqRecover(tx)).toThrow(/import "tronweb\/pq"/);
    });

    it('refuses an oversized pq_auth_sig list before looking for a verifier', () => {
        // The count check precedes every per-entry step, the verifier lookup
        // included, so an unloaded core reports the count, not the import.
        const oversized = {
            ...tx,
            pq_auth_sig: Array.from({ length: PQ_MAX_TOTAL_SIGNATURES + 1 }, () => ({ ...tx.pq_auth_sig[0] })),
        };
        expect(() => Trx.pqRecover(oversized)).toThrow(/too many pq_auth_sig entries: 6 exceeds the node limit of 5/);
    });
});
