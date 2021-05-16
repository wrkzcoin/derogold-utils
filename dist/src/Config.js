"use strict";
// Copyright (c) 2018-2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.
Object.defineProperty(exports, "__esModule", { value: true });
exports.Config = void 0;
/** @ignore */
exports.Config = {
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
    maximumLedgerAPDUPayloadSize: 480,
    minimumLedgerVersion: '1.2.0',
    ledgerDebug: false
};
