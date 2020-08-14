// Copyright (c) 2018-2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

/**
 * Respresents the available coin configuration parameters
 */
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
}

/** @ignore */
export const Config: ICoinRunningConfig = {
    activateParentBlockVersion: 2,
    coinUnitPlaces: 2,
    addressPrefix: 3914525,
    keccakIterations: 1,
    defaultNetworkFee: 10,
    fusionMinInputCount: 12,
    fusionMinInOutCountRatio: 4,
    mmMiningBlockVersion: 2,
    maximumOutputAmount: 100000000000,
    maximumOutputsPerTransaction: 90,
    maximumExtraSize: 1024,
    activateFeePerByteTransactions: true,
    feePerByte: 1.953125,
    feePerByteChunkSize: 256,
    maximumLedgerTransactionSize: 38400,
    maximumLedgerAPDUPayloadSize: 480
};
