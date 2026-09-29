import { ContractParamter, ContractType, CreateSmartContract, TriggerSmartContract } from './Contract.js';
import { PQAuthSig } from './PQ.js';

export interface ContractParamterWrapper<T = ContractParamter> {
    value: T;
    type_url: string;
}
export interface TransactionContract<T = ContractParamter> {
    type: ContractType;
    parameter: ContractParamterWrapper<T>;
    Permission_id?: number;
}

export interface Transaction<T = ContractParamter> {
    visible: boolean;
    txID: string;
    raw_data: {
        contract: TransactionContract<T>[];
        ref_block_bytes: string;
        ref_block_hash: string;
        expiration: number;
        timestamp: number;
        data?: string;
        fee_limit?: number;
    };
    raw_data_hex: string;
}

export interface CreateSmartContractTransaction extends Transaction<CreateSmartContract> {
    /**
     * Address of smart contract.
     */
    contract_address: string;
}

/**
 * `TransactionWrapper` interface is returned when user trigger a smart contract.
 */
export interface TransactionWrapper {
    Error?: string;
    result: {
        result: boolean;
        message?: string;
    };
    /**
     * The transaction object created by calling contract function.
     */
    transaction: Transaction<TriggerSmartContract>;
    /**
     * Energy required for successfully deploying new contract or trigger contract.
     * This is returned in `transactionBuilder.estimateEnergy()` and `transactionBuilder.deployConstantContract()`
     */
    energy_required?: number;
    /**
     * The penalty energy consumption.
     */
    energy_penalty?: number;
    /**
     * Energy used by triggering contract.
     */
    energy_used?: number;
    /**
     * Result of calling contract function which is decorated by `view` or `pure`.
     */
    constant_result?: any;
}

export interface SignedTransaction<T extends ContractParamter = ContractParamter> extends Transaction<T> {
    signature: string[];
    /** Present when the transaction (also) carries post-quantum signatures. */
    pq_auth_sig?: PQAuthSig[];
    contract_address?: string;
}

/**
 * A transaction authorized by post-quantum signatures. `signature` is
 * optional: a pure-PQ transaction has no ECDSA signatures at all, while a
 * mixed multisig carries both fields (their weights sum against the same
 * permission threshold).
 */
export interface PQSignedTransaction<T extends ContractParamter = ContractParamter> extends Transaction<T> {
    pq_auth_sig: PQAuthSig[];
    signature?: string[];
    contract_address?: string;
}

/** Any transaction the node will accept as signed. */
export type AnySignedTransaction<T extends ContractParamter = ContractParamter> =
    | SignedTransaction<T>
    | PQSignedTransaction<T>;
