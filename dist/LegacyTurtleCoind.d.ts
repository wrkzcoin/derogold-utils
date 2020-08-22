import { HTTPClient } from './Helpers/HTTPClient';
import { LegacyTurtleCoindTypes as TurtleCoindInterfaces } from './Types/LegacyTurtleCoind';
/**
 * A class interface that allows for easy interaction with Legacy TurtleCoind
 */
export declare class LegacyTurtleCoind extends HTTPClient implements TurtleCoindInterfaces.ILegacyTurtleCoind {
    /**
     * Retrieves details on a single block by hash
     * @param hash the hash of the block to retrieve
     */
    block(hash: string): Promise<TurtleCoindInterfaces.IBlockSummary>;
    /**
     * Gets the daemon current block count
     */
    blockCount(): Promise<number>;
    /**
     * Retrieves the block header information by hash
     * @param hash the hash of the block to retrieve the header for
     */
    blockHeaderByHash(hash: string): Promise<TurtleCoindInterfaces.IBlockHeader>;
    /**
     * Retrieves the block header by the height
     * @param height the height of the block to retrieve the header for
     */
    blockHeaderByHeight(height: number): Promise<TurtleCoindInterfaces.IBlockHeader>;
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
    blocksDetailed(timestamp?: number, blockHashes?: string[], blockCount?: number): Promise<TurtleCoindInterfaces.IBlocksDetailedResponse>;
    /**
     * Retrieves abbreviated block information for the last 31 blocks before the specified height (inclusive)
     * @param height the height of the block to retrieve
     */
    blockShortHeaders(height: number): Promise<TurtleCoindInterfaces.IBlockShortHeader[]>;
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
    blocksLite(blockHashes: string[], timestamp?: number): Promise<TurtleCoindInterfaces.IBlockLiteResponse>;
    /**
     * Retrieves a block template using the supplied parameters for the tip of the known chain
     * @param walletAddress the wallet address to receive the coinbase transaction outputs
     * @param reserveSize the amount of space in the blocktemplate to reserve for additional data
     */
    blockTemplate(walletAddress: string, reserveSize?: number): Promise<TurtleCoindInterfaces.IBlockTemplate>;
    /**
     * Retrieves the node donation fee information for the given node
     */
    fee(): Promise<TurtleCoindInterfaces.IFeeResponse>;
    /**
     * Retrieves the global output indexes of the given transaction
     * @param transactionHash the hash of the transaction to retrieve
     */
    globalIndexes(transactionHash: string): Promise<number[]>;
    /**
     * Retrieves the global indexes for any transactions in the range [startHeight .. endHeight]. Generally, you
     * only want the global index for a specific transaction, however, this reveals that you probably are the
     * recipient of this transaction. By supplying a range of blocks, you can obfusticate which transaction
     * you are enquiring about.
     * @param startHeight the height to begin returning indices from
     * @param endHeight the height to end returning indices from
     */
    globalIndexesForRange(startHeight: number, endHeight: number): Promise<TurtleCoindInterfaces.IGlobalIndexesResponse[]>;
    /**
     * Retrieves the current daemon height statistics
     */
    height(): Promise<TurtleCoindInterfaces.IHeightResponse>;
    /**
     * Retrieves the current daemon information statistics
     */
    info(): Promise<TurtleCoindInterfaces.IInfoResponse>;
    /**
     * Retrieves the last block header information
     */
    lastBlockHeader(): Promise<TurtleCoindInterfaces.IBlockHeader>;
    /**
     * Retrieves information regarding the daemon's peerlist
     */
    peers(): Promise<TurtleCoindInterfaces.IPeersResponse>;
    /**
     * Retrieves updates regarding the transaction mempool
     * @param tailBlockHash the last block hash that we know about
     * @param knownTransactionHashes an array of the transaction hashes we last knew were in the mempool
     */
    poolChanges(tailBlockHash: string, knownTransactionHashes?: string[]): Promise<TurtleCoindInterfaces.IPoolChanges>;
    /**
     * Retrieves random outputs from the chain for mixing purposes during the creation of a new transaction
     * @param amounts an array of the amounts for which we need random outputs
     * @param mixin the number of random outputs we need for each amount specified
     */
    randomOutputs(amounts: number[], mixin?: number): Promise<TurtleCoindInterfaces.IRandomOutputsResponse>;
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
    rawBlocks(startHeight?: number, startTimestamp?: number, blockHashCheckpoints?: string[], skipCoinbaseTransactions?: boolean, blockCount?: number): Promise<TurtleCoindInterfaces.IRawBlocksResponse>;
    /**
     * Submits a raw transaction to the daemon for processing relaying to the network
     * @param transaction the hex representation of the transaction
     */
    sendRawTransaction(transaction: string): Promise<TurtleCoindInterfaces.ISendRawTransactionResponse>;
    /**
     * Submits a raw block to the daemon for processing and relaying to the network
     * @param blockBlob the hex prepresentation of the block
     */
    submitBlock(blockBlob: string): Promise<string>;
    /**
     * Retrieves a single transaction's information
     * @param hash the hash of the transaction to retrieve
     */
    transaction(hash: string): Promise<TurtleCoindInterfaces.ITransactionResponse>;
    /**
     * Retrieves summary information of the transactions currently in the mempool
     */
    transactionPool(): Promise<TurtleCoindInterfaces.ITransactionSummary[]>;
    /**
     * Retrieves the status of the transaction hashes provided
     * @param transactionHashes an array of transaction hashes to check
     */
    transactionStatus(transactionHashes: string[]): Promise<TurtleCoindInterfaces.ITransactionStatusResponse>;
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
    walletSyncData(startHeight?: number, startTimestamp?: number, blockHashCheckpoints?: string[], skipCoinbaseTransactions?: boolean, blockCount?: number): Promise<TurtleCoindInterfaces.IWalletSyncData>;
}
