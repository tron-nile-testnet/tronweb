import { Permission } from './Contract.js';
import { SignedTransaction, TransactionWrapper } from './Transaction.js';

export interface APIReturnedPermission extends Omit<Permission, 'type'> {
    type?: string;
}
export interface BlockHeaderRawData {
    number: number;
    txTrieRoot: string;
    witness_address: string;
    parentHash: string;
    version: number;
    timestamp: number;
}
export interface BlockHeader {
    raw_data: BlockHeaderRawData;
    /**
     * Absent when the block is produced by a PQ witness: `pq_auth_sig`
     * replaces `witness_signature` entirely (the two are mutually exclusive
     * at block level). Observed live on Nile since Falcon-512 activation.
     */
    witness_signature?: string;
    /** Singular (not an array) at block-header level, unlike transactions. */
    pq_auth_sig?: {
        scheme: string;
        public_key: string;
        signature: string;
    };
}
export interface BlockWithoutDetail {
    blockID: string;
    block_header: BlockHeader;
}

export interface GetTransactionResponse extends Omit<SignedTransaction, 'visible' | 'signature'> {
    /**
     * Absent on a pure-PQ transaction: it is authorized by `pq_auth_sig`
     * alone and the node omits the empty `signature` list entirely (observed
     * on every PQ transaction in `test/fixtures/pq-onchain-transactions.json`).
     * Present, possibly alongside `pq_auth_sig`, whenever ECDSA signed.
     */
    signature?: string[];
    visible?: boolean;
    ret: [
        {
            contractRet: string;
        },
    ];
}

export interface Block {
    blockID: string;
    /** If a block has 0 transaction, this prop will be undefined */
    transactions?: GetTransactionResponse[];
    block_header: BlockHeader;
}

export interface GetSignWeightResponse {
    permission: APIReturnedPermission;
    result: {
        code: string;
    };
    transaction: TransactionWrapper;
}

export interface BlockHeaderRef {
    ref_block_bytes: string;
    ref_block_hash: string;
    expiration: number;
    timestamp: number;
}
