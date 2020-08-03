export declare namespace Interfaces {
    interface Config {
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
        underivePublicKey?: (derivation: string, outputIndex: number, outputKey: string) => Promise<string>;
        derivePublicKey?: (derivation: string, outputIndex: number, publicKey: string) => Promise<string>;
        deriveSecretKey?: (derivation: string, outputIndex: number, privateKey: string) => Promise<string>;
        generateKeyImage?: (transactionPublicKey: string, privateViewKey: string, publicSpendKey: string, privateSpendKey: string, outputIndex: number) => Promise<string>;
        secretKeyToPublicKey?: (privateKey: string) => Promise<string>;
        cn_fast_hash?: (input: string) => Promise<string>;
        generateRingSignatures?: (transactionPrefixHash: Promise<boolean>, keyImage: string, inputKeys: string[], privateKey: string, realIndex: number) => Promise<string[]>;
        checkRingSignatures?: (transactionPrefixHash: string, keyImage: string, publicKeys: string[], signatures: string[]) => Promise<boolean>;
        generateKeyDerivation?: (transactionPublicKey: string, privateViewKey: string) => Promise<string>;
        checkSignature?: (digestHash: string, publicKey: string, signature: string) => boolean;
        generateSignature?: (digestHash: string, publicKey: string, privateKey: string) => Promise<[boolean, string]>;
    }
}
