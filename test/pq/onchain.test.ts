import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFileSync } from 'node:fs';
import { TronWeb } from '../setup/TronWeb.js';
import { createPQSigner, isSchemeEnabled, verifyPQTransaction, PQ_PUBLIC_KEY_SIZES } from '../../src/pq/index.js';
import type { PQSchemeName, TronPQSigner } from '../../src/pq/index.js';
import { Trx } from '../../src/lib/trx/trx.js';
import { txCheck } from '../../src/utils/transaction.js';
import type { AnySignedTransaction, PQSignedTransaction, SignedTransaction } from '../../src/types/Transaction.js';
import { FIXTURE_FALCON_SEED, FIXTURE_MLDSA_SEED, FIXTURE_PATH, PQ_NODE } from './onchainFixtures.js';
import type { OnChainFixture } from './onchainFixtures.js';

/**
 * Node-backed PQ suite: signs, broadcasts and confirms real transactions on a
 * PQ-enabled java-tron node — a local private net with BOTH `getAllowFnDsa512`
 * and `getAllowMlDsa44` active (setup: docs/privnet/README.md). It spends
 * funds and installs a permission, so never point it at Nile or mainnet.
 *
 *     PQ_NODE=http://127.0.0.1:16667 PRIVATE_KEY=<funded ECDSA key> npm run test:pq
 *
 * `PRIVATE_KEY` only funds the throwaway accounts below (and only when they
 * are short). Add `PQ_RECORD_FIXTURES=1` to also rewrite
 * test/fixtures/pq-onchain-transactions.json from the transfers this run gets
 * accepted — then run the offline suite once more, since the recording run
 * itself still loaded the previous fixture. Without `PQ_NODE` + `PRIVATE_KEY`
 * the whole file is skipped and `npm run test:pq` stays offline.
 * `PQ_SOLIDITY_NODE` optionally points solidityNode elsewhere; the suite
 * itself never needs it.
 */
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const RECORD = process.env.PQ_RECORD_FIXTURES === '1';
const NODE_AVAILABLE = Boolean(PQ_NODE && PRIVATE_KEY);

// Every account this suite touches derives from a trivial constant: the two PQ
// fixture seeds, plus an ECDSA key for the mixed-multisig account.
const MIXED_ECDSA_KEY = '33'.repeat(32);
const SCHEMES = ['FN_DSA_512', 'ML_DSA_44'] as const;
// Record mode sends more transfers so the fixture covers several Falcon
// signature lengths (they vary within the 617-667 band).
const TRANSFERS: Record<PQSchemeName, number> = RECORD ? { FN_DSA_512: 5, ML_DSA_44: 3 } : { FN_DSA_512: 1, ML_DSA_44: 1 };
const TRX = 1_000_000; // sun

type OnChainTx = OnChainFixture['tx'];
type AccountPermissions = {
    active_permission?: {
        id: number;
        permission_name: string;
        threshold: number;
        operations?: string;
        keys: { address: string; weight: number }[];
    }[];
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
// Broadcast rejections carry their reason as a hex-encoded string.
const decodeMessage = (message?: string) =>
    message && /^[0-9a-f]+$/i.test(message) ? Buffer.from(message, 'hex').toString() : (message ?? '');
const hexAddress = (address: string) => TronWeb.address.toHex(address).toLowerCase();

describe.skipIf(!NODE_AVAILABLE)('PQ signing against a PQ-enabled node', () => {
    let tronWeb: TronWeb;
    const signers = {} as Record<PQSchemeName, TronPQSigner>;
    const recorded: OnChainFixture[] = [];

    // Only full-node endpoints (`wallet/*`, i.e. the getUnconfirmed* accessors)
    // are used below. getBalance / getAccount / getTransactionInfo go to
    // `walletsolidity/*`, which the private net serves on a separate port
    // (16668) — and solidityNode defaults to PQ_NODE (override:
    // PQ_SOLIDITY_NODE), so with the default they would 405.
    async function confirm(txid: string) {
        for (let attempt = 0; attempt < 40; attempt++) {
            const info = await tronWeb.trx.getUnconfirmedTransactionInfo(txid);
            if (info?.id) return info;
            await sleep(1500);
        }
        throw new Error(`transaction ${txid} not confirmed in time`);
    }

    // The first broadcast after a node (re)start can fail spuriously while it
    // warms up; an identical call seconds later succeeds. Retry a few times,
    // and treat "already have it" as success.
    async function broadcast<T extends AnySignedTransaction>(signed: T) {
        let result = await tronWeb.trx.sendRawTransaction(signed);
        for (let attempt = 1; attempt < 4 && result.result !== true && result.code !== 'DUP_TRANSACTION_ERROR'; attempt++) {
            await sleep(2000);
            result = await tronWeb.trx.sendRawTransaction(signed);
        }
        if (result.code === 'DUP_TRANSACTION_ERROR') result = { ...result, result: true };
        return result;
    }

    // Top up from PRIVATE_KEY only when short, so re-runs on a pre-funded
    // private net (whose genesis already holds these accounts) cost nothing.
    async function fund(address: string, minimum: number, amount: number) {
        if ((await tronWeb.trx.getUnconfirmedBalance(address)) >= minimum) return;
        const res = await tronWeb.trx.sendTransaction(address, amount);
        expect(res.result, `funding ${address}: ${decodeMessage((res as { message?: string }).message)}`).toBe(true);
        await confirm(res.txid);
    }

    beforeAll(async () => {
        tronWeb = new TronWeb({
            fullNode: PQ_NODE!,
            solidityNode: process.env.PQ_SOLIDITY_NODE ?? PQ_NODE!,
            eventServer: PQ_NODE!,
            privateKey: PRIVATE_KEY!,
        });
        signers.FN_DSA_512 = createPQSigner({ scheme: 'FN_DSA_512', privateKey: FIXTURE_FALCON_SEED });
        signers.ML_DSA_44 = createPQSigner({ scheme: 'ML_DSA_44', privateKey: FIXTURE_MLDSA_SEED });
        for (const scheme of SCHEMES) {
            if (!(await isSchemeEnabled(tronWeb, scheme))) {
                throw new Error(`${scheme} is not active on ${PQ_NODE} — this suite needs a node with both PQ schemes enabled`);
            }
        }
        for (const signer of Object.values(signers)) await fund(signer.address, 50 * TRX, 100 * TRX);
    }, 180_000);

    afterAll(() => {
        if (!RECORD || recorded.length === 0) return;
        const byScheme = (scheme: PQSchemeName) =>
            recorded.filter((f) => f.tx.pq_auth_sig[0].scheme === scheme).sort((a, b) => a.block - b.block);
        const out = [...byScheme('FN_DSA_512'), ...byScheme('ML_DSA_44')];
        writeFileSync(FIXTURE_PATH, JSON.stringify(out, null, 2) + '\n');
        console.log(`PQ_RECORD_FIXTURES: wrote ${out.length} transactions to ${FIXTURE_PATH}`);
    });

    describe.each(SCHEMES)('%s transfer', (scheme) => {
        it.each(Array.from({ length: TRANSFERS[scheme] }, (_, i) => i))(
            '#%i is accepted, executed, and echoed back byte-for-byte',
            async (i) => {
                const signer = signers[scheme];
                const recipient = signers[scheme === 'FN_DSA_512' ? 'ML_DSA_44' : 'FN_DSA_512'];
                const before = await tronWeb.trx.getUnconfirmedBalance(signer.address);

                const tx = await tronWeb.transactionBuilder.sendTrx(recipient.address, 1_000 + i, signer.address);
                const signed = await tronWeb.trx.signPQ(tx, signer);
                expect(signed.signature).toBeUndefined();
                expect(signed.pq_auth_sig).toHaveLength(1);
                const entry = signed.pq_auth_sig[0];
                expect(entry.scheme).toBe(scheme);
                expect(entry.public_key.length / 2).toBe(PQ_PUBLIC_KEY_SIZES[scheme]);
                expect(verifyPQTransaction(signed, { txCheck })).toMatchObject({ valid: true, txIdMatchesPayload: true });
                expect(Trx.getPQSignerAddresses(signed)).toEqual([signer.address]);

                const res = await broadcast(signed);
                expect(res.result, `${res.code}: ${decodeMessage(res.message)}`).toBe(true);
                const info = await confirm(res.txid);
                expect(info.blockNumber).toBeGreaterThan(0);

                const onchain = (await tronWeb.trx.getTransaction(res.txid)) as unknown as OnChainTx;
                expect(onchain.ret?.[0]?.contractRet).toBe('SUCCESS');
                expect(onchain.txID).toBe(signed.txID);
                expect(onchain.raw_data_hex).toBe(signed.raw_data_hex);
                // scheme, public_key and signature must come back exactly as sent
                expect(onchain.pq_auth_sig).toEqual([entry]);
                expect(onchain.signature).toBeUndefined();
                expect(await tronWeb.trx.getUnconfirmedBalance(signer.address)).toBeLessThan(before);

                recorded.push({ block: info.blockNumber, tx: onchain });
            },
            120_000
        );
    });

    describe('the node fails closed on malformed pq_auth_sig entries (bypassing attachPQAuthSig)', () => {
        // Bypass attachPQAuthSig on purpose: mutate the entry AFTER signing and
        // hand it straight to broadcast. Each case must die at the node's
        // admission gate, never reach consensus, and never cost a fee.
        async function rejectedWith(mutate: (signed: PQSignedTransaction) => void) {
            const signer = signers.FN_DSA_512;
            const tx = await tronWeb.transactionBuilder.sendTrx(signers.ML_DSA_44.address, 1_000, signer.address);
            const signed = await tronWeb.trx.signPQ(tx, signer);
            mutate(signed);
            const res = await tronWeb.trx.sendRawTransaction(signed);
            expect(res.result).not.toBe(true);
            return `${res.code}: ${decodeMessage(res.message)}`;
        }

        it('a duplicate PQ signer can never double-count its weight', async () => {
            // Two guards sit in front of weight summing: a permission holding
            // fewer keys than entries fails the count check first ("pq_auth_sig
            // count 2 exceeds permission key count 1" — the default owner
            // permission has one key); a wider permission reaches the
            // per-address check instead ("<addr> has signed twice!"). Either
            // way the duplicate never counts.
            const why = await rejectedWith((s) => s.pq_auth_sig.push({ ...s.pq_auth_sig[0] }));
            expect(why).toMatch(/signed twice|exceeds permission key count/);
        });

        it('an 897-byte Falcon key (NIST framing header left on) is out of bounds', async () => {
            const why = await rejectedWith((s) => {
                s.pq_auth_sig[0].public_key = '09' + s.pq_auth_sig[0].public_key;
            });
            expect(why).toMatch(/out of bounds/);
        });

        it('a signature below the 617-byte floor is out of bounds', async () => {
            const why = await rejectedWith((s) => {
                s.pq_auth_sig[0].signature = '39' + 'ab'.repeat(600);
            });
            expect(why).toMatch(/out of bounds/);
        });

        it('a tampered signature of a valid length is a signature error', async () => {
            const why = await rejectedWith((s) => {
                const sig = s.pq_auth_sig[0].signature;
                s.pq_auth_sig[0].signature = sig.slice(0, -2) + (sig.endsWith('00') ? '01' : '00');
            });
            expect(why).toMatch(/SIGERROR/);
        });
    });

    describe('mixed ECDSA + PQ multisig: weights sum against one threshold', () => {
        const owner = TronWeb.address.fromPrivateKey(MIXED_ECDSA_KEY) as string;
        let permissionId: number;

        beforeAll(async () => {
            const falcon = signers.FN_DSA_512;
            // Reuse the 2-of-2 permission if an earlier run installed it —
            // same keys AND weights, threshold 2, TransferContract allowed.
            const wanted = [owner, falcon.address]
                .map((a) => `${hexAddress(a)}:1`)
                .sort()
                .join();
            const account = (await tronWeb.trx.getUnconfirmedAccount(owner)) as unknown as AccountPermissions;
            const existing = account.active_permission?.find(
                (p) =>
                    p.permission_name === 'mixed' &&
                    p.threshold === 2 &&
                    // bit 1 of the ContractType bitmap = TransferContract
                    (parseInt((p.operations ?? '00').slice(0, 2), 16) & 0x02) !== 0 &&
                    p.keys
                        .map((k) => `${hexAddress(k.address)}:${k.weight}`)
                        .sort()
                        .join() === wanted
            );
            if (existing) {
                permissionId = existing.id;
                await fund(owner, 5 * TRX, 20 * TRX); // just the two transfers below
                return;
            }
            // AccountPermissionUpdateContract costs 100 TRX; paid once, then
            // the permission is reused by later runs.
            await fund(owner, 120 * TRX, 150 * TRX);
            const permTx = await tronWeb.transactionBuilder.updateAccountPermissions(
                owner,
                { type: 0, permission_name: 'owner', threshold: 1, keys: [{ address: owner, weight: 1 }] },
                undefined,
                [
                    {
                        type: 2,
                        permission_name: 'mixed',
                        threshold: 2, // neither key alone can authorize
                        // ContractType bitmap: bit 1 = TransferContract, all this
                        // suite needs (a mainnet-wide bitmap names types a PQ
                        // build may not define).
                        operations: '02' + '00'.repeat(31),
                        keys: [
                            { address: owner, weight: 1 },
                            { address: falcon.address, weight: 1 },
                        ],
                    },
                ]
            );
            const res = await broadcast(await tronWeb.trx.sign(permTx, MIXED_ECDSA_KEY));
            expect(res.result, `${res.code}: ${decodeMessage(res.message)}`).toBe(true);
            await confirm(res.txid);
            const installed = (
                (await tronWeb.trx.getUnconfirmedAccount(owner)) as unknown as AccountPermissions
            ).active_permission?.find((p) => p.permission_name === 'mixed');
            expect(installed?.threshold).toBe(2);
            permissionId = installed!.id;
        }, 180_000);

        it('one ECDSA signature is weight 1 of 2 and the node rejects the broadcast', async () => {
            const tx = await tronWeb.transactionBuilder.sendTrx(signers.ML_DSA_44.address, 1_000, owner, { permissionId });
            const solo = await tronWeb.trx.multiSign(tx, MIXED_ECDSA_KEY, permissionId);
            const weight = await tronWeb.trx.getSignWeight(solo, permissionId);
            expect(weight.current_weight).toBe(1);
            const res = await tronWeb.trx.sendRawTransaction(solo);
            expect(res.result).not.toBe(true);
        });

        it('ECDSA + Falcon together reach weight 2, get accepted, and both signers recover from the on-chain tx', async () => {
            const tx = await tronWeb.transactionBuilder.sendTrx(signers.ML_DSA_44.address, 1_000, owner, { permissionId });
            const ecdsaSigned = await tronWeb.trx.multiSign(tx, MIXED_ECDSA_KEY, permissionId);
            expect(ecdsaSigned.signature).toHaveLength(1);
            expect(ecdsaSigned.pq_auth_sig ?? []).toHaveLength(0);

            const mixed = await tronWeb.trx.multiSign(ecdsaSigned, signers.FN_DSA_512, permissionId);
            expect(mixed.signature).toHaveLength(1);
            expect(mixed.pq_auth_sig).toHaveLength(1);

            const both = [owner, signers.FN_DSA_512.address].sort();
            const weight = await tronWeb.trx.getSignWeight(mixed, permissionId);
            expect(weight.current_weight).toBe(2);
            expect((weight.approved_list ?? []).map((a) => TronWeb.address.fromHex(a)).sort()).toEqual(both);

            const res = await broadcast(mixed);
            expect(res.result, `${res.code}: ${decodeMessage(res.message)}`).toBe(true);
            const info = await confirm(res.txid);
            expect(info.blockNumber).toBeGreaterThan(0);

            const onchain = (await tronWeb.trx.getTransaction(res.txid)) as unknown as SignedTransaction & OnChainTx;
            expect(onchain.ret?.[0]?.contractRet).toBe('SUCCESS');
            expect(onchain.signature).toHaveLength(1);
            expect(onchain.pq_auth_sig).toHaveLength(1);
            expect((Trx.ecRecover(onchain) as string[]).sort()).toEqual(both);
            expect(verifyPQTransaction(onchain, { txCheck })).toMatchObject({ valid: true, txIdMatchesPayload: true });
        }, 120_000);
    });
});
