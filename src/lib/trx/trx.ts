import { TronWeb } from '../../tronweb.js';
import utils from '../../utils/index.js';
import { keccak256, toUtf8Bytes, recoverAddress, SigningKey, Signature } from '../../utils/ethersUtils.js';
import { ADDRESS_PREFIX } from '../../utils/constants.js';
import { fromHex, toHex } from '../../utils/address.js';
import { AbstractTrx } from './AbstractTrx.js';
import { RawTrx } from './RawTrx.js';
import { txCheck, txCheckWithArgs } from '../../utils/transaction.js';
import { cloneTransaction } from '../../utils/clone.js';
import { ecRecover, pqPublicKeyToAddress } from '../../utils/crypto.js';
import { BroadcastReturn, AddressOptions, BroadcastHexReturn, Address } from '../../types/Trx.js';
import { AnySignedTransaction, PQSignedTransaction, SignedTransaction, Transaction } from '../../types/Transaction.js';
import { TronPQSigner, isTronPQSigner } from '../../types/PQ.js';
import { TypedDataDomain, TypedDataField } from '../../utils/typedData.js';
import { Resource } from '../../types/TransactionBuilder.js';

const TRX_MESSAGE_HEADER = '\x19TRON Signed Message:\n32';
// it should be: '\x15TRON Signed Message:\n32';
const ETH_MESSAGE_HEADER = '\x19Ethereum Signed Message:\n32';

type SignedStringOrSignedTransaction<T extends string | Transaction | SignedTransaction> = T extends string
    ? string
    : SignedTransaction & T;

export class Trx extends AbstractTrx<false> {
    protected readonly int64AsString = false as const;

    /** Raw (string-int64) variants of the chain reads, see {@link RawTrx}. */
    readonly raw: RawTrx;
    /** Blocks the plugin system from overriding the `raw` sub-module at runtime. */
    pluginNoOverride = ['raw'];

    signMessage;
    sendAsset;
    send;
    sendTrx;
    broadcast;
    broadcastHex;
    signTransaction;

    constructor(tronWeb: TronWeb) {
        super(tronWeb);

        this.raw = new RawTrx(tronWeb);
        this.signMessage = this.sign;
        this.sendAsset = this.sendToken;
        this.send = this.sendTransaction;
        this.sendTrx = this.sendTransaction;
        this.broadcast = this.sendRawTransaction;
        this.broadcastHex = this.sendHexTransaction;
        this.signTransaction = this.sign;
    }

    ecRecover(transaction: SignedTransaction) {
        return Trx.ecRecover(transaction);
    }

    static ecRecover(transaction: SignedTransaction): Address | Address[] {
        const tx = cloneTransaction(transaction);
        if (!txCheck(tx)) {
            throw new Error('Invalid transaction');
        }
        if (!tx.signature?.length) {
            if (tx.pq_auth_sig?.length) {
                throw new Error(
                    'Transaction is signed with post-quantum signatures; ECDSA recovery does not apply. ' +
                        'Use getPQSignerAddresses instead.'
                );
            }
            throw new Error('Transaction is not signed');
        }
        const txID = tx.txID;
        // Mixed multisig: PQ co-signers are part of the signer set, so a
        // recovery that listed only the ECDSA participants would misreport
        // the transaction as under-signed.
        const pqAddresses = (tx.pq_auth_sig ?? []).map((entry) =>
            TronWeb.address.fromHex(pqPublicKeyToAddress(entry.public_key, entry.scheme))
        );
        if (tx.signature.length === 1 && !pqAddresses.length) {
            const tronAddress = ecRecover(txID, tx.signature[0]);
            return TronWeb.address.fromHex(tronAddress);
        }
        return [
            ...tx.signature.map((sig) => {
                const tronAddress = ecRecover(txID, sig);
                return TronWeb.address.fromHex(tronAddress);
            }),
            ...pqAddresses,
        ];
    }

    getPQSignerAddresses(transaction: PQSignedTransaction): Address[] {
        return Trx.getPQSignerAddresses(transaction);
    }

    /**
     * Derive the signer addresses of a PQ-signed transaction from the public
     * keys embedded in its `pq_auth_sig` entries. PQ schemes have no
     * ecrecover-style primitive, but none is needed — the full public key
     * travels with the signature. Note this derives, it does not verify: use
     * `verifyPQTransaction` from `tronweb/pq` to check the signatures.
     */
    static getPQSignerAddresses(transaction: PQSignedTransaction): Address[] {
        const tx = cloneTransaction(transaction);
        if (!txCheck(tx)) {
            throw new Error('Invalid transaction');
        }
        if (!tx.pq_auth_sig?.length) {
            throw new Error('Transaction has no pq_auth_sig entries');
        }
        // Scheme-strict, as the node is: an entry whose key is the other
        // scheme's size throws here instead of listing a signer the node
        // would reject ("public key or signature length mismatch").
        return tx.pq_auth_sig.map((entry) => TronWeb.address.fromHex(pqPublicKeyToAddress(entry.public_key, entry.scheme)));
    }

    async verifyMessage(message: string, signature: string, address = this.tronWeb.defaultAddress.base58, useTronHeader = true) {
        if (!utils.isHex(message)) {
            throw new Error('Expected hex message input');
        }

        if (Trx.verifySignature(message, address as string, signature, useTronHeader)) {
            return true;
        }

        throw new Error('Signature does not match');
    }

    static verifySignature(message: string, address: string, signature: string, useTronHeader = true) {
        message = message.replace(/^0x/, '');
        const messageBytes = [
            ...toUtf8Bytes(useTronHeader ? TRX_MESSAGE_HEADER : ETH_MESSAGE_HEADER),
            ...utils.code.hexStr2byteArray(message),
        ];

        const messageDigest = keccak256(new Uint8Array(messageBytes));
        const recovered = recoverAddress(messageDigest, Signature.from(`0x${signature.replace(/^0x/, '')}`));

        const tronAddress = ADDRESS_PREFIX + recovered.substr(2);
        const base58Address = TronWeb.address.fromHex(tronAddress);

        return base58Address == TronWeb.address.fromHex(address);
    }

    async verifyMessageV2(message: string | Uint8Array | Array<number>, signature: string) {
        return Trx.verifyMessageV2(message, signature);
    }

    static verifyMessageV2(message: string | Uint8Array | Array<number>, signature: string) {
        return utils.message.verifyMessage(message, signature);
    }

    verifyTypedData(
        domain: TypedDataDomain,
        types: Record<string, TypedDataField[]>,
        value: Record<string, any>,
        signature: string,
        address = this.tronWeb.defaultAddress.base58
    ) {
        if (Trx.verifyTypedData(domain, types, value, signature, address as string)) return true;

        throw new Error('Signature does not match');
    }

    static verifyTypedData(
        domain: TypedDataDomain,
        types: Record<string, TypedDataField[]>,
        value: Record<string, any>,
        signature: string,
        address: string
    ) {
        const messageDigest = utils.typedData.hashTypedData(domain, types, value);
        const recovered = recoverAddress(messageDigest, Signature.from(`0x${signature.replace(/^0x/, '')}`));

        const tronAddress = ADDRESS_PREFIX + recovered.substr(2);
        const base58Address = TronWeb.address.fromHex(tronAddress);

        return base58Address == TronWeb.address.fromHex(address);
    }

    async sign<T extends SignedTransaction | Transaction | string>(
        transaction: T,
        privateKey?: string | false,
        useTronHeader?: boolean,
        multisig?: boolean
    ): Promise<SignedStringOrSignedTransaction<T>>;
    async sign<T extends SignedTransaction | Transaction>(
        transaction: T,
        signer: TronPQSigner,
        useTronHeader?: boolean,
        multisig?: boolean
    ): Promise<PQSignedTransaction & T>;
    async sign<T extends SignedTransaction | Transaction | string>(
        transaction: T,
        privateKey: string | false | TronPQSigner = this.tronWeb.defaultPrivateKey,
        useTronHeader = true,
        multisig = false
    ): Promise<SignedStringOrSignedTransaction<T> | (PQSignedTransaction & T)> {
        // Message signing
        if (utils.isString(transaction)) {
            if (isTronPQSigner(privateKey)) {
                throw new Error('PQ signers can only sign transactions; message signing has no PQ protocol support');
            }
            if (!utils.isHex(transaction)) {
                throw new Error('Expected hex message input');
            }

            return Trx.signString(transaction, privateKey as string, useTronHeader) as SignedStringOrSignedTransaction<T>;
        }

        if (!utils.isObject(transaction)) {
            throw new Error('Invalid transaction provided');
        }

        const tx = cloneTransaction(transaction as Transaction | SignedTransaction);

        if (!multisig && ((tx as SignedTransaction).signature || (tx as PQSignedTransaction).pq_auth_sig?.length)) {
            throw new Error('Transaction is already signed');
        }

        if (!multisig) {
            const address = isTronPQSigner(privateKey)
                ? toHex(privateKey.address).toLowerCase()
                : toHex(this.tronWeb.address.fromPrivateKey(privateKey as string) as string).toLowerCase();

            if (address !== toHex(tx.raw_data.contract[0].parameter.value.owner_address)) {
                throw new Error('Private key does not match address in transaction');
            }
        }

        if (!txCheck(tx)) {
            throw new Error('Invalid transaction');
        }

        if (isTronPQSigner(privateKey)) {
            const signature = await privateKey.signDigest(tx.txID);
            return utils.crypto.attachPQAuthSig(tx, {
                scheme: privateKey.scheme,
                public_key: privateKey.publicKey,
                signature,
            }) as PQSignedTransaction & T;
        }

        return utils.crypto.signTransaction(privateKey as string, tx) as SignedStringOrSignedTransaction<T>;
    }

    /**
     * Dedicated post-quantum signing entry point — `sign()` restricted to a
     * `TronPQSigner`. Exists for discoverability and misuse resistance: a
     * private-key string here is a compile-time AND runtime error, so a PQ
     * call site can never silently fall back to ECDSA.
     */
    async signPQ<T extends SignedTransaction | Transaction>(
        transaction: T,
        signer: TronPQSigner,
        multisig = false
    ): Promise<PQSignedTransaction & T> {
        if (!isTronPQSigner(signer)) {
            throw new Error(
                'signPQ requires a TronPQSigner (see createPQSigner in tronweb/pq); to sign with a private key use sign()'
            );
        }
        return this.sign(transaction, signer, true, multisig);
    }

    static signString(message: string, privateKey: string, useTronHeader = true) {
        message = message.replace(/^0x/, '');
        const value = `0x${privateKey.replace(/^0x/, '')}`;
        const signingKey = new SigningKey(value);
        const messageBytes = [
            ...toUtf8Bytes(useTronHeader ? TRX_MESSAGE_HEADER : ETH_MESSAGE_HEADER),
            ...utils.code.hexStr2byteArray(message),
        ];
        const messageDigest = keccak256(new Uint8Array(messageBytes));
        const signature = signingKey.sign(messageDigest);
        const signatureHex = ['0x', signature.r.substring(2), signature.s.substring(2), Number(signature.v).toString(16)].join(
            ''
        );
        return signatureHex;
    }

    /**
     * sign message v2 for verified header length
     *
     * @param {message to be signed, should be Bytes or string} message
     * @param {privateKey for signature} privateKey
     * @param {reserved} options
     */
    signMessageV2(message: string | Uint8Array | Array<number>, privateKey = this.tronWeb.defaultPrivateKey) {
        return Trx.signMessageV2(message, privateKey as string);
    }

    static signMessageV2(message: string | Uint8Array | Array<number>, privateKey: string) {
        return utils.message.signMessage(message, privateKey);
    }

    _signTypedData(
        domain: TypedDataDomain,
        types: Record<string, TypedDataField[]>,
        value: Record<string, any>,
        privateKey = this.tronWeb.defaultPrivateKey
    ) {
        return Trx._signTypedData(domain, types, value, privateKey as string);
    }

    static _signTypedData(
        domain: TypedDataDomain,
        types: Record<string, TypedDataField[]>,
        value: Record<string, any>,
        privateKey: string
    ) {
        return utils.typedData.signTypedData(domain, types, value, privateKey);
    }

    signTypedData(
        domain: TypedDataDomain,
        types: Record<string, TypedDataField[]>,
        value: Record<string, any>,
        privateKey = this.tronWeb.defaultPrivateKey
    ) {
        return Trx.signTypedData(domain, types, value, privateKey as string);
    }

    static signTypedData(
        domain: TypedDataDomain,
        types: Record<string, TypedDataField[]>,
        value: Record<string, any>,
        privateKey: string
    ) {
        return utils.typedData.signTypedData(domain, types, value, privateKey);
    }

    async multiSign(transaction: Transaction, privateKey?: string | false, permissionId?: number): Promise<SignedTransaction>;
    async multiSign(transaction: Transaction, signer: TronPQSigner, permissionId?: number): Promise<PQSignedTransaction>;
    async multiSign(
        transaction: Transaction,
        privateKey: string | false | TronPQSigner = this.tronWeb.defaultPrivateKey,
        permissionId = 0
    ): Promise<SignedTransaction | PQSignedTransaction> {
        if (!utils.isObject(transaction)) {
            throw new Error('Invalid transaction provided');
        }

        transaction = cloneTransaction(transaction);

        if (!transaction.raw_data || !transaction.raw_data.contract) {
            throw new Error('Invalid transaction provided');
        }

        // If owner permission or permission id exists in transaction, do sign directly
        // If no permission id inside transaction or user passes permission id, use old way to reset permission id
        if (!transaction.raw_data.contract[0].Permission_id && permissionId > 0) {
            // set permission id
            transaction.raw_data.contract[0].Permission_id = permissionId;

            // check if the signing key is inside the permission list. PQ signers
            // appear there by their derived address, same as ECDSA keys.
            const address = isTronPQSigner(privateKey)
                ? toHex(privateKey.address).toLowerCase()
                : toHex(this.tronWeb.address.fromPrivateKey(privateKey as string) as string).toLowerCase();
            const signWeight = await this.getSignWeight(transaction, permissionId);

            if (signWeight.result.code === 'PERMISSION_ERROR') {
                throw new Error(signWeight.result.message);
            }

            let foundKey = false;
            signWeight.permission.keys.map((key) => {
                if (key.address.toLowerCase() === address) foundKey = true;
            });

            if (!foundKey) {
                throw new Error('Address ' + fromHex(address) + ' has no permission to sign');
            }

            if (signWeight.approved_list && signWeight.approved_list.some((approved) => approved.toLowerCase() === address)) {
                throw new Error('Address ' + fromHex(address) + ' already sign transaction');
            }

            // reset transaction
            if (signWeight.transaction && signWeight.transaction.transaction) {
                // Verify the fullNode returned the transaction we asked it to weigh before
                // adopting it, so we never sign a transaction the node may have substituted.
                // Permission_id was set above (which changes the txID), so it is included in
                // the args used to re-derive and compare the returned transaction.
                const returnedTransaction = signWeight.transaction.transaction;
                const args = { ...transaction.raw_data.contract[0].parameter.value, Permission_id: permissionId };
                // txCheckWithArgs rebuilds the checked transaction from its own contract
                // type and block-header fields (ref block, expiration, timestamp), so a
                // substituted type or header would be self-consistent — overwrite them with
                // the submitted transaction's values, forcing the returned raw_data_hex/txID
                // to match the contract type and header we sent.
                const localRawData = transaction.raw_data;
                const checkedTransaction = {
                    ...returnedTransaction,
                    raw_data: {
                        ...returnedTransaction.raw_data,
                        contract: [
                            {
                                ...returnedTransaction.raw_data.contract[0],
                                type: localRawData.contract[0].type,
                            },
                            ...returnedTransaction.raw_data.contract.slice(1),
                        ],
                        ref_block_bytes: localRawData.ref_block_bytes,
                        ref_block_hash: localRawData.ref_block_hash,
                        expiration: localRawData.expiration,
                        timestamp: localRawData.timestamp,
                    },
                };
                if (!txCheckWithArgs(checkedTransaction, args, localRawData)) {
                    throw new Error('Invalid transaction provided');
                }

                transaction = returnedTransaction;
                if (permissionId > 0) {
                    transaction.raw_data.contract[0].Permission_id = permissionId;
                }
            } else {
                throw new Error('Invalid transaction provided');
            }
        }

        // sign
        if (!txCheck(transaction)) {
            throw new Error('Invalid transaction');
        }
        if (isTronPQSigner(privateKey)) {
            const signature = await privateKey.signDigest(transaction.txID);
            return utils.crypto.attachPQAuthSig(transaction as PQSignedTransaction, {
                scheme: privateKey.scheme,
                public_key: privateKey.publicKey,
                signature,
            });
        }
        return utils.crypto.signTransaction(privateKey as string, transaction);
    }

    async sendRawTransaction<T extends AnySignedTransaction>(signedTransaction: T): Promise<BroadcastReturn<T>> {
        if (!utils.isObject(signedTransaction)) {
            throw new Error('Invalid transaction provided');
        }

        // Both fields use the same rule: an empty array is unsigned (the node
        // rejects it as "miss sig or contract").
        const hasEcdsaSignatures = utils.isArray(signedTransaction.signature) && signedTransaction.signature.length > 0;
        const hasPQSignatures = utils.isArray(signedTransaction.pq_auth_sig) && signedTransaction.pq_auth_sig.length > 0;
        if (!hasEcdsaSignatures && !hasPQSignatures) {
            throw new Error('Transaction is not signed');
        }

        const result = await this.tronWeb.fullNode.request<Omit<BroadcastReturn<T>, 'transaction'>>(
            'wallet/broadcasttransaction',
            signedTransaction,
            'post'
        );
        return {
            ...result,
            transaction: signedTransaction,
        };
    }

    async sendHexTransaction(signedHexTransaction: string) {
        if (!utils.isHex(signedHexTransaction)) {
            throw new Error('Invalid hex transaction provided');
        }

        const params = {
            transaction: signedHexTransaction,
        };

        const result = await this.tronWeb.fullNode.request<BroadcastHexReturn>('wallet/broadcasthex', params, 'post');
        if (result.result) {
            return {
                ...result,
                transaction: JSON.parse(result.transaction) as Transaction,
                hexTransaction: signedHexTransaction,
            };
        }
        return result;
    }

    async sendTransaction(to: string, amount: number, options: AddressOptions = {}): Promise<BroadcastReturn<SignedTransaction>> {
        if (typeof options === 'string') options = { privateKey: options };

        if (!this.tronWeb.isAddress(to)) {
            throw new Error('Invalid recipient provided');
        }

        if (!utils.isInteger(amount) || amount <= 0) {
            throw new Error('Invalid amount provided');
        }

        options = {
            privateKey: this.tronWeb.defaultPrivateKey as string,
            address: this.tronWeb.defaultAddress.hex as string,
            ...options,
        };

        if (!options.privateKey && !options.address) {
            throw new Error('Function requires either a private key or address to be set');
        }

        const address = options.privateKey ? this.tronWeb.address.fromPrivateKey(options.privateKey) : options.address;
        const transaction = await this.tronWeb.transactionBuilder.sendTrx(to, amount, address as Address);
        const signedTransaction = await this.sign(transaction, options.privateKey);
        const result = await this.sendRawTransaction(signedTransaction);
        return result;
    }

    async sendToken(
        to: string,
        amount: number,
        tokenID: string | number,
        options: AddressOptions = {}
    ): Promise<BroadcastReturn<SignedTransaction>> {
        if (typeof options === 'string') options = { privateKey: options };

        if (!this.tronWeb.isAddress(to)) {
            throw new Error('Invalid recipient provided');
        }

        if (!utils.isInteger(amount) || amount <= 0) {
            throw new Error('Invalid amount provided');
        }

        if (utils.isInteger(tokenID)) tokenID = tokenID.toString();

        if (!utils.isString(tokenID)) {
            throw new Error('Invalid token ID provided');
        }

        options = {
            privateKey: this.tronWeb.defaultPrivateKey as string,
            address: this.tronWeb.defaultAddress.hex as string,
            ...options,
        };

        if (!options.privateKey && !options.address) {
            throw new Error('Function requires either a private key or address to be set');
        }

        const address = options.privateKey ? this.tronWeb.address.fromPrivateKey(options.privateKey) : options.address;
        const transaction = await this.tronWeb.transactionBuilder.sendToken(to, amount, tokenID, address as Address);
        const signedTransaction = await this.sign(transaction, options.privateKey);
        const result = await this.sendRawTransaction(signedTransaction);
        return result;
    }

    /**
     * Freezes an amount of TRX.
     * Will give bandwidth OR Energy and TRON Power(voting rights)
     * to the owner of the frozen tokens.
     *
     * @param amount - is the number of frozen trx
     * @param duration - is the duration in days to be frozen
     * @param resource - is the type, must be either "ENERGY" or "BANDWIDTH"
     * @param options
     */
    async freezeBalance(
        amount = 0,
        duration = 3,
        resource: Resource = 'BANDWIDTH',
        options: AddressOptions = {},
        receiverAddress?: string
    ): Promise<BroadcastReturn<SignedTransaction>> {
        if (typeof options === 'string') options = { privateKey: options };

        if (!['BANDWIDTH', 'ENERGY'].includes(resource)) {
            throw new Error('Invalid resource provided: Expected "BANDWIDTH" or "ENERGY"');
        }

        if (!utils.isInteger(amount) || amount <= 0) {
            throw new Error('Invalid amount provided');
        }

        if (!utils.isInteger(duration) || duration < 3) {
            throw new Error('Invalid duration provided, minimum of 3 days');
        }

        options = {
            privateKey: this.tronWeb.defaultPrivateKey as string,
            address: this.tronWeb.defaultAddress.hex as string,
            ...options,
        };

        if (!options.privateKey && !options.address) {
            throw new Error('Function requires either a private key or address to be set');
        }

        const address = options.privateKey ? this.tronWeb.address.fromPrivateKey(options.privateKey) : options.address;
        const freezeBalance = await this.tronWeb.transactionBuilder.freezeBalance(
            amount,
            duration,
            resource,
            address as Address,
            receiverAddress
        );
        const signedTransaction = await this.sign(freezeBalance, options.privateKey);
        const result = await this.sendRawTransaction(signedTransaction);
        return result;
    }

    /**
     * Unfreeze TRX that has passed the minimum freeze duration.
     * Unfreezing will remove bandwidth and TRON Power.
     *
     * @param resource - is the type, must be either "ENERGY" or "BANDWIDTH"
     * @param options
     */
    async unfreezeBalance(
        resource: Resource = 'BANDWIDTH',
        options: AddressOptions = {},
        receiverAddress: string
    ): Promise<BroadcastReturn<SignedTransaction>> {
        if (typeof options === 'string') options = { privateKey: options };

        if (!['BANDWIDTH', 'ENERGY'].includes(resource)) {
            throw new Error('Invalid resource provided: Expected "BANDWIDTH" or "ENERGY"');
        }

        options = {
            privateKey: this.tronWeb.defaultPrivateKey as string,
            address: this.tronWeb.defaultAddress.hex as string,
            ...options,
        };

        if (!options.privateKey && !options.address) {
            throw new Error('Function requires either a private key or address to be set');
        }

        const address = options.privateKey ? this.tronWeb.address.fromPrivateKey(options.privateKey) : options.address;
        const unfreezeBalance = await this.tronWeb.transactionBuilder.unfreezeBalance(
            resource,
            address as Address,
            receiverAddress
        );
        const signedTransaction = await this.sign(unfreezeBalance, options.privateKey);
        const result = await this.sendRawTransaction(signedTransaction);
        return result;
    }

    /**
     * Modify account name
     * Note: Username is allowed to edit only once.
     *
     * @param privateKey - Account private Key
     * @param accountName - name of the account
     *
     * @return modified Transaction Object
     */
    async updateAccount(accountName: string, options: AddressOptions = {}): Promise<BroadcastReturn<SignedTransaction>> {
        if (typeof options === 'string') options = { privateKey: options };

        if (!utils.isString(accountName) || !accountName.length) {
            throw new Error('Name must be a string');
        }

        options = {
            privateKey: this.tronWeb.defaultPrivateKey as string,
            address: this.tronWeb.defaultAddress.hex as string,
            ...options,
        };

        if (!options.privateKey && !options.address) throw Error('Function requires either a private key or address to be set');

        const address = options.privateKey ? this.tronWeb.address.fromPrivateKey(options.privateKey) : options.address;
        const updateAccount = await this.tronWeb.transactionBuilder.updateAccount(accountName, address as Address);
        const signedTransaction = await this.sign(updateAccount, options.privateKey);
        const result = await this.sendRawTransaction(signedTransaction);
        return result;
    }
}
