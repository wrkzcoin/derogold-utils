import { HTTPClient } from './Helpers/HTTPClient';
import { TurtleCoindTypes } from './Types/TurtleCoind';
/**
 * A class interface that allows for easy interaction with TurtleCoind
 */
export declare class TurtleCoind extends HTTPClient implements TurtleCoindTypes.ITurtleCoind {
    /**
     * Retrieves the node fee information
     */
    fee(): Promise<TurtleCoindTypes.IFee>;
    /**
     * Retrieves the node height information
     */
    height(): Promise<TurtleCoindTypes.IHeight>;
    /**
     * Retrieves the node information
     */
    info(): Promise<TurtleCoindTypes.IInfo>;
    /**
     * Retrieves the node peer information
     */
    peers(): Promise<TurtleCoindTypes.IPeers>;
    /**
     * Retrieves the number of blocks the node has in its chain
     */
    blockCount(): Promise<number>;
    /**
     * Retrieves the block information for the specified block
     * Requires the daemon to have the explorer enabled
     * @param block the block height or hash
     */
    block(block: string | number): Promise<TurtleCoindTypes.IBlock>;
    /**
     * Retrieves the block information for the last block available
     */
    lastBlock(): Promise<TurtleCoindTypes.IBlock>;
    /**
     * Retrieves the block information for the last 30 blocks up to the current height
     * Requires the daemon to have the explorer enabled
     * @param height the height to stop at
     */
    blockHeaders(height: number): Promise<TurtleCoindTypes.IBlock[]>;
    /**
     * Retrieves the RawBlock information from the node for the specified block
     * Requires the daemon to have the explorer enabled
     * @param block the block height or hash
     */
    rawBlock(block: string | number): Promise<TurtleCoindTypes.IRawBlock>;
    /**
     * Retrieves a mining block template using the specified address and reserve size
     * @param address the wallet address that will receive the coinbase outputs
     * @param reserveSize the amount of data to reserve in the miner transaction
     */
    blockTemplate(address: string, reserveSize?: number): Promise<TurtleCoindTypes.IBlockTemplate>;
    /**
     * Submits a block to the node for processing
     * @param block the hex representation of the block
     */
    submitBlock(block: string): Promise<string>;
    /**
     * Submits a transaction to the node for processing
     * @param transaction the hex representation of the transaction
     */
    submitTransaction(transaction: string): Promise<string>;
    /**
     * Retrieves the transaction information for the specified transaction
     * Requires the daemon to have the explorer enabled
     * @param hash the transaction hash
     */
    transaction(hash: string): Promise<TurtleCoindTypes.ITransaction>;
    /**
     * Retrieves the RawTransaction from the node for the specified transaction
     * Requires the daemon to have the explorer enabled
     * @param hash the transaction hash
     */
    rawTransaction(hash: string): Promise<string>;
    /**
     * Retrieves the transaction summary information for the transactions currently
     * Requires the daemon to have the explorer enabled
     * in the memory pool
     */
    transactionPool(): Promise<TurtleCoindTypes.TransactionSummary[]>;
    /**
     * Retrieves the RawTransactions currently in the memory pool
     * Requires the daemon to have the explorer enabled
     */
    rawTransactionPool(): Promise<string[]>;
    /**
     * Gets the transaction memory pool changes given the last known block hash and
     * the transactions we last knew to be in the memory pool
     * @param lastKnownBlock the last known block hash
     * @param transactions an array of transaction hashes we last saw in the memory pool
     */
    transactionPoolChanges(lastKnownBlock: string, transactions?: string[]): Promise<TurtleCoindTypes.ITransactionPoolDelta>;
    /**
     * Retrieves information on where the specified transactions are located
     * @param transactions an array of transaction hashes
     */
    transactionsStatus(transactions: string[]): Promise<TurtleCoindTypes.ITransactionsStatus>;
    /**
     * Retrieves random global indexes typically used for mixing operations for the specified
     * amounts and for the number requested (if available)
     * @param amounts an array of amounts for which we need random global indexes
     * @param count the number of global indexes to return for each amount
     */
    randomIndexes(amounts: number[], count?: number): Promise<TurtleCoindTypes.IRandomOutput[]>;
    /**
     * Retrieves the global indexes for all transactions contained within the blocks heights specified (non-inclusive)
     * @param startHeight the starting block height
     * @param endHeight the ending block height
     */
    indexes(startHeight: number, endHeight: number): Promise<TurtleCoindTypes.ITransactionIndexes[]>;
    /**
     * Retrieves the information necessary for syncing a wallet (or other utility) against the node
     * @param checkpoints a list of block hashes that we know about in descending height order
     * @param height the height to start syncing from
     * @param timestamp the timestamp to start syncing from
     * @param skipCoinbaseTransactions whether we should skip blocks that only include coinbase transactions
     * @param count the number of blocks to return
     */
    sync(checkpoints?: string[], height?: number, timestamp?: number, skipCoinbaseTransactions?: boolean, count?: number): Promise<TurtleCoindTypes.ISync>;
    /**
     * Retrieves the RawBlocks & RawTransactions for syncing a wallet (or other utility) against the node
     * @param checkpoints a list of block hashes that we know about in descending height order
     * @param height the height to start syncing from
     * @param timestamp the timestamp to start syncing from
     * @param skipCoinbaseTransactions whether we should skip blocks that only include coinbase transactions
     * @param count the number of blocks to return
     */
    rawSync(checkpoints?: string[], height?: number, timestamp?: number, skipCoinbaseTransactions?: boolean, count?: number): Promise<TurtleCoindTypes.IRawSync>;
}
