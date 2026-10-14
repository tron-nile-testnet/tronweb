import { describe, it, expect } from 'vitest';
import { Trx } from '../../src/lib/trx/trx.js';
import { toHex } from '../../src/utils/address.js';
import { PQ_MAX_TOTAL_SIGNATURES } from '../../src/types/PQ.js';
import * as pqVerifier from '../../src/utils/pqVerifier.js';
import { falconFixtures, mlDsaFixtures } from './onchainFixtures.js';
import type { OnChainFixture } from './onchainFixtures.js';

// This file deliberately never imports the `tronweb/pq` entry (src/pq/index.ts).
// It exercises the main entry on its own, the way an application that loaded
// only `tronweb` does — and the way `tronweb` is loaded in an ESM/CJS
// dual-package install: `require('tronweb')` and `import 'tronweb/pq'` resolve
// to separate copies under lib/commonjs and lib/esm, so nothing `tronweb/pq`
// does at import time can reach the `Trx` the application holds. pqRecover
// must therefore verify with what the core itself carries, and it must not
// degrade to deriving an address from the public key, which would name a
// signer it never checked. (vitest isolates each test file's module graph, so
// the other PQ test files' `src/pq/index` imports do not leak in here.)
describe('Trx.pqRecover from the main entry alone (tronweb/pq never imported)', () => {
    const clone = (f: OnChainFixture) => JSON.parse(JSON.stringify(f.tx)) as OnChainFixture['tx'];
    const owner = (tx: OnChainFixture['tx']) => tx.raw_data.contract[0].parameter.value.owner_address.toLowerCase();

    it('verifies an on-chain FN_DSA_512 transaction and recovers its owner', () => {
        const tx = clone(falconFixtures[0]);
        const addresses = Trx.pqRecover(tx);
        expect(addresses).toHaveLength(1);
        expect(toHex(addresses[0])).toBe(owner(tx));
    });

    it('verifies an on-chain ML_DSA_44 transaction and recovers its owner', () => {
        const tx = clone(mlDsaFixtures[0]);
        const addresses = Trx.pqRecover(tx);
        expect(addresses).toHaveLength(1);
        expect(toHex(addresses[0])).toBe(owner(tx));
    });

    it('refuses a tampered entry: the built-in verifier is the real one, not a permissive stub', () => {
        const tx = clone(falconFixtures[0]);
        const sig = tx.pq_auth_sig[0].signature;
        tx.pq_auth_sig[0].signature = sig.slice(0, -2) + (sig.endsWith('00') ? '01' : '00');
        expect(() => Trx.pqRecover(tx)).toThrow(/pq_auth_sig\[0\] \(FN_DSA_512\) does not verify/);
    });

    it('refuses an oversized pq_auth_sig list before verifying any entry', () => {
        const tx = clone(falconFixtures[0]);
        const oversized = {
            ...tx,
            pq_auth_sig: Array.from({ length: PQ_MAX_TOTAL_SIGNATURES + 1 }, () => ({ ...tx.pq_auth_sig[0] })),
        };
        expect(() => Trx.pqRecover(oversized)).toThrow(/too many pq_auth_sig entries: 6 exceeds the node limit of 5/);
    });

    it('has no registration step that another copy of the package could miss', () => {
        // The verifiers are a fixed table bound at load time: an import side
        // effect running in a different copy of `tronweb` can neither add to
        // it nor be required by it.
        expect((pqVerifier as Record<string, unknown>).registerPQVerifier).toBeUndefined();
        expect(Object.keys(pqVerifier.PQ_VERIFIERS).sort()).toEqual(['FN_DSA_512', 'ML_DSA_44']);
    });
});
