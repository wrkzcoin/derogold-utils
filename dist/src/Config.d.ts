/** @ignore */
export interface ICoinConfig {
    activateParentBlockVersion?: number;
    coinUnitPlaces?: number;
    addressPrefix?: number;
    keccakIterations?: number;
    defaultNetworkFee?: number;
    fusionMinInputCount?: number;
    fusionMinInOutCountRatio?: number;
    mmMiningBlockVersion?: number;
    maximumOutputAmount?: number;
    maximumOutputsPerTransaction?: number;
    maximumExtraSize?: number;
    activateFeePerByteTransactions?: boolean;
    feePerByte?: number;
    feePerByteChunkSize?: number;
    maximumLedgerTransactionSize?: number;
    maximumLedgerAPDUPayloadSize?: number;
    minimumLedgerVersion?: string;
    ledgerDebug?: boolean;
    [key: string]: any;
}
/** @ignore */
export interface ICoinRunningConfig extends ICoinConfig {
    activateParentBlockVersion: number;
    coinUnitPlaces: number;
    addressPrefix: number;
    keccakIterations: number;
    defaultNetworkFee: number;
    fusionMinInputCount: number;
    fusionMinInOutCountRatio: number;
    mmMiningBlockVersion: number;
    maximumOutputAmount: number;
    maximumOutputsPerTransaction: number;
    maximumExtraSize: number;
    activateFeePerByteTransactions: boolean;
    feePerByte: number;
    feePerByteChunkSize: number;
    maximumLedgerTransactionSize: number;
    maximumLedgerAPDUPayloadSize: number;
    minimumLedgerVersion: string;
    ledgerDebug: boolean;
}
/** @ignore */
export declare const Config: ICoinRunningConfig;
