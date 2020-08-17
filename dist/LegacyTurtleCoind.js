"use strict";
// Copyright (c) 2018-2020, Brandon Lehmann, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LegacyTurtleCoind = void 0;
const HTTPClient_1 = require("./Helpers/HTTPClient");
const BigInteger = require("big-integer");
/**
 * A class interface that allows for easy interaction with Legacy TurtleCoind
 */
class LegacyTurtleCoind extends HTTPClient_1.HTTPClient {
    /**
     * Retrieves details on a single block by hash
     * @param hash the hash of the block to retrieve
     */
    block(hash) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.rpcPost('f_block_json', { hash });
            response.block.alreadyGeneratedCoins = BigInteger(response.block.alreadyGeneratedCoins);
            return response.block;
        });
    }
    /**
     * Gets the daemon current block count
     */
    blockCount() {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.rpcPost('getblockcount');
            return response.count;
        });
    }
    /**
     * Retrieves the block header information by hash
     * @param hash the hash of the block to retrieve the header for
     */
    blockHeaderByHash(hash) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.rpcPost('getblockheaderbyhash', { hash });
            return response.block_header;
        });
    }
    /**
     * Retrieves the block header by the height
     * @param height the height of the block to retrieve the header for
     */
    blockHeaderByHeight(height) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.rpcPost('getblockheaderbyheight', { height });
            return response.block_header;
        });
    }
    /**
     * Retrieves up to 100 blocks. If block hashes are given, it will return beginning from the height of the
     * first hash it finds, plus one. However, if timestamp is given, and this value is higher than any found
     * in the array of blockHashes, it will start returning blocks from that height instead. The blockHashes
     * array should be given the highest block height hashes first, then in descending order by height.
     * First 10 block hashes go sequential, next in pow(2,n) offset (ie. 2, 4, 8, 16, 32, 64...), and the
     * last block hash is always the genesis block.
     * Typical usage: specify a start timestamp initially, and from then on, also provide the returned block
     * hashes as mentioned above.
     * @param timestamp the timestamp to start from
     * @param blockHashes the array of block hashes
     * @param blockCount the number of blocks to return
     */
    blocksDetailed(timestamp = 0, blockHashes = [], blockCount = 100) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield this.post('queryblocksdetailed', {
                blockIds: blockHashes,
                timestamp: timestamp,
                blockCount: blockCount
            });
            for (const block of result.blocks) {
                block.alreadyGeneratedCoins = BigInteger(block.alreadyGeneratedCoins);
                for (const txn of block.transactions) {
                    txn.unlockTime = BigInteger(txn.unlockTime);
                }
            }
            return result;
        });
    }
    /**
     * Retrieves abbreviated block information for the last 31 blocks before the specified height (inclusive)
     * @param height the height of the block to retrieve
     */
    blockShortHeaders(height) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.rpcPost('f_blocks_list_json', { height });
            return response.blocks;
        });
    }
    /**
     * Retrieves up to 100 blocks. If block hashes are given, it will return beginning from the height of the
     * first hash it finds, plus one. However, if timestamp is given, and this value is higher than any found
     * in the array of blockHashes, it will start returning blocks from that height instead. The blockHashes
     * array should be given the highest block height hashes first, then in descending order by height.
     * First 10 block hashes go sequential, next in pow(2,n) offset (ie. 2, 4, 8, 16, 32, 64...), and the
     * last block hash is always the genesis block.
     * Typical usage: specify a start timestamp initially, and from then on, also provide the returned block
     * hashes as mentioned above.
     * @param blockHashes
     * @param timestamp
     */
    blocksLite(blockHashes, timestamp = 0) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.post('queryblockslite', {
                blockIds: blockHashes,
                timestamp: timestamp
            });
            const tmp = [];
            for (const item of response.items) {
                const transactions = [];
                for (const txn of item['blockShortInfo.txPrefixes']) {
                    transactions.push({
                        hash: txn['transactionPrefixInfo.txHash'],
                        prefix: txn['transactionPrefixInfo.txPrefix']
                    });
                }
                for (const txn of transactions) {
                    txn.prefix.unlock_time = BigInteger(txn.prefix.unlock_time);
                }
                tmp.push({
                    block: Buffer.from(item['blockShortInfo.block']).toString('hex'),
                    hash: item['blockShortInfo.blockId'],
                    transactions: transactions
                });
            }
            response.items = tmp;
            return response;
        });
    }
    /**
     * Retrieves a block template using the supplied parameters for the tip of the known chain
     * @param walletAddress the wallet address to receive the coinbase transaction outputs
     * @param reserveSize the amount of space in the blocktemplate to reserve for additional data
     */
    blockTemplate(walletAddress, reserveSize = 8) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.rpcPost('getblocktemplate', {
                reserve_size: reserveSize,
                wallet_address: walletAddress
            });
        });
    }
    /**
     * Retrieves the node donation fee information for the given node
     */
    fee() {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.get('fee');
            response.amount = BigInteger(response.amount);
            return response;
        });
    }
    /**
     * Retrieves the global output indexes of the given transaction
     * @param transactionHash the hash of the transaction to retrieve
     */
    globalIndexes(transactionHash) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.post('get_o_indexes', {
                txid: transactionHash
            });
            if (response.status.toLowerCase() !== 'ok') {
                throw new Error('Transaction not found');
            }
            return response.o_indexes;
        });
    }
    /**
     * Retrieves the global indexes for any transactions in the range [startHeight .. endHeight]. Generally, you
     * only want the global index for a specific transaction, however, this reveals that you probably are the
     * recipient of this transaction. By supplying a range of blocks, you can obfusticate which transaction
     * you are enquiring about.
     * @param startHeight the height to begin returning indices from
     * @param endHeight the height to end returning indices from
     */
    globalIndexesForRange(startHeight, endHeight) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.post('get_global_indexes_for_range', { startHeight, endHeight });
            if (!response.status || !response.indexes) {
                throw new Error('Missing indexes or status key');
            }
            if (response.status.toLowerCase() !== 'ok') {
                throw new Error('Status is not OK');
            }
            return response.indexes;
        });
    }
    /**
     * Retrieves the current daemon height statistics
     */
    height() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.get('height');
        });
    }
    /**
     * Retrieves the current daemon information statistics
     */
    info() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.get('info');
        });
    }
    /**
     * Retrieves the last block header information
     */
    lastBlockHeader() {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.rpcPost('getlastblockheader');
            return response.block_header;
        });
    }
    /**
     * Retrieves information regarding the daemon's peerlist
     */
    peers() {
        return __awaiter(this, void 0, void 0, function* () {
            return this.get('peers');
        });
    }
    /**
     * Retrieves updates regarding the transaction mempool
     * @param tailBlockHash the last block hash that we know about
     * @param knownTransactionHashes an array of the transaction hashes we last knew were in the mempool
     */
    poolChanges(tailBlockHash, knownTransactionHashes = []) {
        return __awaiter(this, void 0, void 0, function* () {
            const body = {
                tailBlockId: tailBlockHash
            };
            if (knownTransactionHashes)
                body.knownTxsIds = knownTransactionHashes;
            const response = yield this.post('get_pool_changes_lite', body);
            const tmp = [];
            for (const tx of response.addedTxs) {
                tmp.push({
                    hash: tx['transactionPrefixInfo.txHash'],
                    prefix: tx['transactionPrefixInfo.txPrefix']
                });
            }
            for (const tx of tmp) {
                tx.prefix.unlock_time = BigInteger(tx.prefix.unlock_time);
            }
            response.addedTxs = tmp;
            return response;
        });
    }
    /**
     * Retrieves random outputs from the chain for mixing purposes during the creation of a new transaction
     * @param amounts an array of the amounts for which we need random outputs
     * @param mixin the number of random outputs we need for each amount specified
     */
    randomOutputs(amounts, mixin = 1) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.post('getrandom_outs', {
                amounts: amounts,
                outs_count: mixin
            });
        });
    }
    /**
     * Retrieves the raw hex representation of each block and the transactions in the blocks versus returning
     * JSON or other encoded versions of the same.
     *
     * Retrieves up to 100 blocks. If block hash checkpoints are given, it will return beginning from the height of
     * the first hash it finds, plus one. However, if startHeight or startTimestamp is given, and this value is
     * higher than the block hash checkpoints, it will start returning from that height instead. The block hash
     * checkpoints should be given with the highest block height hashes first.
     * Typical usage: specify a start height/timestamp initially, and from then on, also provide the returned
     * block hashes.
     * @param startHeight the height to start returning blocks from
     * @param startTimestamp the timestamp to start returning blocks from
     * @param blockHashCheckpoints the block hash checkpoints
     * @param skipCoinbaseTransactions whether to skip returning blocks with only coinbase transactions
     * @param blockCount the number of blocks to retrieve
     */
    rawBlocks(startHeight = 0, startTimestamp = 0, blockHashCheckpoints = [], skipCoinbaseTransactions = false, blockCount = 100) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.post('getrawblocks', {
                startHeight: startHeight,
                startTimestamp: startTimestamp,
                blockHashCheckpoints: blockHashCheckpoints,
                skipCoinbaseTransactions: skipCoinbaseTransactions,
                blockCount: blockCount
            });
        });
    }
    /**
     * Submits a raw transaction to the daemon for processing relaying to the network
     * @param transaction the hex representation of the transaction
     */
    sendRawTransaction(transaction) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.post('sendrawtransaction', { tx_as_hex: transaction });
        });
    }
    /**
     * Submits a raw block to the daemon for processing and relaying to the network
     * @param blockBlob the hex prepresentation of the block
     */
    submitBlock(blockBlob) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.rpcPost('submitblock', [blockBlob]);
            return response.status;
        });
    }
    /**
     * Retrieves a single transaction's information
     * @param hash the hash of the transaction to retrieve
     */
    transaction(hash) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.rpcPost('f_transaction_json', { hash });
            if (response.tx && response.tx['']) {
                delete response.tx[''];
            }
            response.tx.unlock_time = BigInteger(response.tx.unlock_time);
            return response;
        });
    }
    /**
     * Retrieves summary information of the transactions currently in the mempool
     */
    transactionPool() {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.rpcPost('f_on_transactions_pool_json');
            return response.transactions;
        });
    }
    /**
     * Retrieves the status of the transaction hashes provided
     * @param transactionHashes an array of transaction hashes to check
     */
    transactionStatus(transactionHashes) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.post('get_transactions_status', { transactionHashes });
            if (!response.status ||
                !response.transactionsInPool ||
                !response.transactionsInBlock ||
                !response.transactionsUnknown) {
                throw new Error('Missing status of transactions key');
            }
            if (response.status.toLowerCase() !== 'ok') {
                throw new Error('Status is not ok');
            }
            return {
                transactionsInPool: response.transactionsInPool,
                transactionsInBlock: response.transactionsInBlock,
                transactionsUnknown: response.transactionsUnknown
            };
        });
    }
    /**
     * The only the data necessary for wallet syncing purposes
     *
     * Retrieves up to 100 blocks. If block hash checkpoints are given, it will return beginning from the height of
     * the first hash it finds, plus one. However, if startHeight or startTimestamp is given, and this value is
     * higher than the block hash checkpoints, it will start returning from that height instead. The block hash
     * checkpoints should be given with the highest block height hashes first.
     * Typical usage: specify a start height/timestamp initially, and from then on, also provide the returned
     * block hashes.
     * @param startHeight the height to start returning blocks from
     * @param startTimestamp the timestamp to start returning blocks from
     * @param blockHashCheckpoints the block hash checkpoints
     * @param skipCoinbaseTransactions whether to skip returning blocks with only coinbase transactions
     * @param blockCount the number of blocks to request
     */
    walletSyncData(startHeight = 0, startTimestamp = 0, blockHashCheckpoints = [], skipCoinbaseTransactions = false, blockCount = 100) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield this.post('getwalletsyncdata', {
                startHeight: startHeight,
                startTimestamp: startTimestamp,
                blockHashCheckpoints: blockHashCheckpoints,
                skipCoinbaseTransactions: skipCoinbaseTransactions,
                blockCount: blockCount
            });
            if (!response.status || !response.items)
                throw new Error('Missing items or status key');
            if (response.status.toLowerCase() !== 'ok')
                throw new Error('Status is not OK');
            for (const block of response.items) {
                block.coinbaseTX.unlockTime = BigInteger(block.coinbaseTX.unlockTime);
                for (const txn of block.transactions) {
                    txn.unlockTime = BigInteger(txn.unlockTime);
                }
            }
            return response;
        });
    }
}
exports.LegacyTurtleCoind = LegacyTurtleCoind;
