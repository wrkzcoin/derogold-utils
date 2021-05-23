// Copyright (c) 2018-2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

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
    TransactionPowDifficulty?: number;
    FusionTransactionPowDifficulty?: number;
    TransactionPowHeight?: number;
    maximumLedgerTransactionSize?: number;
    maximumLedgerAPDUPayloadSize?: number;
    minimumLedgerVersion?: string;
    ledgerDebug?: boolean
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
    TransactionPowDifficulty: number;
    FusionTransactionPowDifficulty: number;
    TransactionPowHeight: number;
    TransactionPoWHeightDynV1: number;
    TransactionPoWDifficultyDynV1: number;
    MultiplierTransactionPoWDifficultyPerIOV1: number;
    MultiplierTransactionPoWDifficultyFactoredOutV1: number;
    FusionTransactionPoWDifficultyV2: number;
    maximumLedgerTransactionSize: number;
    maximumLedgerAPDUPayloadSize: number;
    minimumLedgerVersion: string;
    ledgerDebug: boolean
}

/** @ignore TODO: Update fork height TransactionPoWHeightDynV1 */
export const Config: ICoinRunningConfig = {
    activateParentBlockVersion: 2,
    coinUnitPlaces: 2,
    addressPrefix: 3914525,
    keccakIterations: 1,
    defaultNetworkFee: 5,
    fusionMinInputCount: 12,
    fusionMinInOutCountRatio: 4,
    mmMiningBlockVersion: 2,
    maximumOutputAmount: 500000000000,
    maximumOutputsPerTransaction: 90,
    maximumExtraSize: 1024,
    activateFeePerByteTransactions: true,
    feePerByte: 1.953125,
    feePerByteChunkSize: 256,
    TransactionPowDifficulty: 20000,
    FusionTransactionPowDifficulty: 60000,
    TransactionPowHeight: 1123000,
    TransactionPoWHeightDynV1: 1400000,
    TransactionPoWDifficultyDynV1: 40000,
    MultiplierTransactionPoWDifficultyPerIOV1: 1000,
    MultiplierTransactionPoWDifficultyFactoredOutV1: 4,
    FusionTransactionPoWDifficultyV2: 320000,
    maximumLedgerTransactionSize: 38400,
    maximumLedgerAPDUPayloadSize: 480,
    minimumLedgerVersion: '1.2.0',
    ledgerDebug: false
};
