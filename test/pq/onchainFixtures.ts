import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { PQSignedTransaction } from '../../src/types/Transaction.js';
import type { TransferContract } from '../../src/types/Contract.js';

/**
 * On-chain PQ fixtures: transactions a PQ-enabled java-tron node accepted and
 * executed, pinned so the offline suite verifies real wire bytes without a
 * node. Nothing here is a real Nile / mainnet account:
 *
 * - Every signer is a throwaway key derived from one of the trivial seeds
 *   below, so a test can re-derive the owner from the seed and prove the
 *   whole seed → key → address → accepted-by-node chain.
 * - The file is (re)written by `test/pq/onchain.test.ts` in record mode
 *   against a local PQ-enabled private net (setup: docs/privnet/README.md):
 *
 *       PQ_NODE=http://127.0.0.1:16667 PRIVATE_KEY=<funded ECDSA key> \
 *         PQ_RECORD_FIXTURES=1 npm run test:pq
 *
 *   `block` is that private net's height — meaningful only as an ordering.
 */
export const FIXTURE_FALCON_SEED = '22'.repeat(48);
export const FIXTURE_MLDSA_SEED = '11'.repeat(32);

/** The PQ-enabled node the node-backed suite targets; unset = that suite is skipped. */
export const PQ_NODE = process.env.PQ_NODE; // e.g. http://127.0.0.1:16667
/**
 * Endpoint handed to the offline tests' TronWeb instances. They never issue a
 * request — the value only has to be a syntactically valid local URL. It
 * defaults to the private net's port from docs/privnet/README.md.
 */
export const LOCAL_NODE = PQ_NODE ?? 'http://127.0.0.1:16667';

export const FIXTURE_PATH = join(__dirname, '../fixtures/pq-onchain-transactions.json');

export interface OnChainFixture {
    block: number;
    tx: PQSignedTransaction<TransferContract> & { ret?: { contractRet: string }[] };
}

export const fixtures: OnChainFixture[] = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'));

const pureSigned = (scheme: string) => (f: OnChainFixture) =>
    !f.tx.signature && f.tx.pq_auth_sig.length === 1 && f.tx.pq_auth_sig[0].scheme === scheme;

/** Pure-PQ transfers (no ECDSA signature, one entry) by scheme; index 0 is the canonical sample. */
export const falconFixtures = fixtures.filter(pureSigned('FN_DSA_512'));
export const mlDsaFixtures = fixtures.filter(pureSigned('ML_DSA_44'));
