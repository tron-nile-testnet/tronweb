import { describe, it, expect } from 'vitest';
import * as pqVerifier from '../../src/utils/pqVerifier.js';
import { PQ_VERIFIERS, getPQVerifier } from '../../src/utils/pqVerifier.js';
import { PQ_PUBLIC_KEY_SIZES } from '../../src/types/PQ.js';
import * as FnDsa512 from '../../src/pq/FnDsa512.js';
import * as MlDsa44 from '../../src/pq/MlDsa44.js';

describe('utils/pqVerifier: fixed verifier table', () => {
    it('binds every supported scheme to its module verifier at load time', () => {
        // One verifier per scheme the core knows a key size for — a scheme
        // added to one table without the other is caught here.
        expect(Object.keys(PQ_VERIFIERS).sort()).toEqual(Object.keys(PQ_PUBLIC_KEY_SIZES).sort());
        expect(PQ_VERIFIERS.FN_DSA_512).toBe(FnDsa512.verify);
        expect(PQ_VERIFIERS.ML_DSA_44).toBe(MlDsa44.verify);
        expect(getPQVerifier('FN_DSA_512')).toBe(FnDsa512.verify);
        expect(getPQVerifier('ML_DSA_44')).toBe(MlDsa44.verify);
    });

    it('is not a registry: nothing can be added to it and there is no register function', () => {
        expect(Object.isFrozen(PQ_VERIFIERS)).toBe(true);
        expect((pqVerifier as Record<string, unknown>).registerPQVerifier).toBeUndefined();
    });

    it('answers undefined, never an inherited function, for a scheme name it does not carry', () => {
        // The scheme is wire data: a name chosen by whoever built the
        // transaction must not reach Object.prototype and come back callable.
        for (const name of ['NOPE', '', 'fn_dsa_512', 'constructor', 'toString', 'hasOwnProperty', '__proto__']) {
            expect(getPQVerifier(name)).toBeUndefined();
        }
    });
});
