import { defineConfig } from 'vitest/config';
import path from 'node:path';

// PQ test run. By default it is offline: no provisioned accounts and no
// local java-tron node, so it skips the main config's globalSetup — the KAT
// vectors and on-chain fixtures make it self-contained. Set PQ_NODE (a
// PQ-enabled node) and PRIVATE_KEY (a funded ECDSA key on it) to also run
// the node-backed suite, test/pq/onchain.test.ts.
const sutEntry = path.resolve(import.meta.dirname, 'test/setup/TronWeb.ts');

export default defineConfig({
    resolve: {
        alias: [{ find: /^(?:\.\.?\/)+setup\/TronWeb\.js$/, replacement: sutEntry }],
    },
    test: {
        globals: true,
        environment: 'node',
        include: ['test/pq/**/*.test.ts'],
        testTimeout: 60000,
        pool: 'forks',
    },
});
