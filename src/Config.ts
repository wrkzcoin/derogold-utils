// Copyright (c) 2018-2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

export namespace Interfaces {
    export interface Config {
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

        underivePublicKey?: (derivation: string,
                             outputIndex: number,
                             outputKey: string) => string;

        derivePublicKey?: (derivation: string,
                           outputIndex: number,
                           publicKey: string) => string;

        deriveSecretKey?: (derivation: string,
                           outputIndex: number,
                           privateKey: string) => string;

        generateKeyImage?: (transactionPublicKey: string,
                            privateViewKey: string,
                            publicSpendKey: string,
                            privateSpendKey: string,
                            outputIndex: number) => string;

        secretKeyToPublicKey?: (privateKey: string) => string;

        cn_fast_hash?: (input: string) => string;

        generateRingSignatures?: (transactionPrefixHash: string,
                                  keyImage: string,
                                  inputKeys: string[],
                                  privateKey: string,
                                  realIndex: number) => string[];

        checkRingSignatures?: (transactionPrefixHash: string,
                               keyImage: string,
                               publicKeys: string[],
                               signatures: string[]) => boolean;

        generateKeyDerivation?: (transactionPublicKey: string,
                                 privateViewKey: string) => string;

        checkSignature?: (digestHash: string,
                          publicKey: string,
                          signature: string) => boolean;

        generateSignature?: (digestHash: string,
                             publicKey: string,
                             privateKey: string) => [boolean, string];
    }
}
