/// <reference types="ledgerhq__hw-transport" />
/// <reference types="node" />
import Transport from '@ledgerhq/hw-transport';
import { EventEmitter } from 'events';
export declare namespace LedgerWalletTypes {
    /** @ignore */
    enum APDU {
        P2 = 0,
        P1_NON_CONFIRM = 0,
        P1_CONFIRM = 1,
        INS = 224
    }
    enum TransactionState {
        INACTIVE = 0,
        READY = 1,
        RECEIVING_INPUTS = 2,
        INPUTS_RECEIVED = 3,
        RECEIVING_OUTPUTS = 4,
        OUTPUTS_RECEIVED = 5,
        PREFIX_READY = 6,
        COMPLETE = 7
    }
    /**
     * Represents the APDU command types available in the TurtleCoin application
     * for ledger hardware wallets
     */
    enum CMD {
        VERSION = 1,
        DEBUG = 2,
        IDENT = 5,
        PUBLIC_KEYS = 16,
        VIEW_SECRET_KEY = 17,
        SPEND_ESECRET_KEY = 18,
        CHECK_KEY = 22,
        CHECK_SCALAR = 23,
        PRIVATE_TO_PUBLIC = 24,
        RANDOM_KEY_PAIR = 25,
        ADDRESS = 48,
        GENERATE_KEY_IMAGE = 64,
        GENERATE_RING_SIGNATURES = 80,
        COMPLETE_RING_SIGNATURE = 81,
        CHECK_RING_SIGNATURES = 82,
        GENERATE_SIGNATURE = 85,
        CHECK_SIGNATURE = 86,
        GENERATE_KEY_DERIVATION = 96,
        DERIVE_PUBLIC_KEY = 97,
        DERIVE_SECRET_KEY = 98,
        TX_STATE = 112,
        TX_START = 113,
        TX_START_INPUT_LOAD = 114,
        TX_LOAD_INPUT = 115,
        TX_START_OUTPUT_LOAD = 116,
        TX_LOAD_OUTPUT = 117,
        TX_FINALIZE_TX_PREFIX = 118,
        TX_SIGN = 119,
        TX_DUMP = 120,
        TX_RESET = 121,
        RESET_KEYS = 255
    }
    /**
     * Represents the possible errors returned by the application
     * on the ledger device
     */
    enum ErrorCode {
        OK = 36864,
        ERR_OP_NOT_PERMITTED = 16384,
        ERR_OP_USER_REQUIRED = 16385,
        ERR_UNKNOWN_ERROR = 17476,
        ERR_VARINT_DATA_RANGE = 24576,
        ERR_PRIVATE_SPEND = 37888,
        ERR_PRIVATE_VIEW = 37889,
        ERR_RESET_KEYS = 37890,
        ERR_ADDRESS = 37968,
        ERR_KEY_DERIVATION = 38144,
        ERR_DERIVE_PUBKEY = 38145,
        ERR_PUBKEY_MISMATCH = 38146,
        ERR_DERIVE_SECKEY = 38147,
        ERR_KECCAK = 38148,
        ERR_COMPLETE_RING_SIG = 38149,
        ERR_GENERATE_KEY_IMAGE = 38150,
        ERR_SECKEY_TO_PUBKEY = 38151
    }
}
/**
 * An easy to use interface that uses a Ledger HW transport to communicate with
 * the TurtleCoin application running on a ledger device.
 * Please see. See https://github.com/LedgerHQ/ledgerjs for available transport providers
 */
export declare class LedgerDevice extends EventEmitter {
    private readonly m_transport;
    /**
     * Creates a new instance of the Ledger interface
     * The transport MUST be connected already before passing to this constructor
     * @param transport See https://github.com/LedgerHQ/ledgerjs for available transport providers
     */
    constructor(transport: Transport);
    /**
     * Returns the underlying transport
     */
    get transport(): Transport;
    /**
     * Event that is emitted right before the raw bytes are sent via the APDU transport
     * @param event the event name
     * @param listener the listener function
     */
    on(event: 'send', listener: (data: string) => void): this;
    /**
     * Emits the raw bytes received from the APDU transport in response to a request
     * @param event the event name
     * @param listener the listener function
     */
    on(event: 'receive', listener: (data: string) => void): this;
    /**
     * Retrieves the current version of the application running
     * on the ledger device
     */
    getVersion(): Promise<{
        major: number;
        minor: number;
        patch: number;
    }>;
    /**
     * Returns if the application running on the ledger is a debug build
     */
    isDebug(): Promise<boolean>;
    /**
     * Retrieves the current identification bytes of the application
     * running on the ledger device
     */
    getIdent(): Promise<string>;
    /**
     * Checks to confirm that the key is a valid public key
     * @param key the key to check
     */
    checkKey(key: string): Promise<boolean>;
    /**
     * Checks to confirm that the scalar is indeed a scalar value
     * @param scalar the scalar to check
     */
    checkScalar(scalar: string): Promise<boolean>;
    /**
     * Retrieves the public keys from the connected ledger device
     * @param confirm whether the device will prompt the user to confirm their actions
     *        (to disable, must be running a DEBUG build)
     */
    getPublicKeys(confirm?: boolean): Promise<{
        spend: string;
        view: string;
    }>;
    /**
     * Retrieves the private view key from the connected ledger device
     * @param confirm whether the device will prompt the user to confirm their actions
     *        (to disable, must be running a DEBUG build)
     */
    getPrivateViewKey(confirm?: boolean): Promise<string>;
    /**
     * Retrieves the private spend key from the connected ledger device
     * !! WARNING !! Retrieving the private spend key from the device
     * may result in a complete loss of funds as the private spend key
     * should normally remain on the device and never leave
     *
     * @param confirm whether the device will prompt the user to confirm their actions
     *        (to disable, must be running a DEBUG build)
     */
    getPrivateSpendKey(confirm?: boolean): Promise<string>;
    /**
     * Calculates the public key for the given private key
     * @param private_key the private key
     */
    privateToPublic(private_key: string): Promise<string>;
    /**
     * Generates a random key pair on the connected device
     */
    getRandomKeyPair(): Promise<{
        public: string;
        private: string;
    }>;
    /**
     * Gets the public wallet address from the connected device
     * @param confirm whether the device will prompt the user to confirm their actions
     *        (to disable, must be running a DEBUG build)
     */
    getAddress(confirm?: boolean): Promise<string>;
    /**
     * Generates a key image on the device using the supplied parameters
     * @param tx_public_key the transaction public key
     * @param output_index the index of the given output in the transaction
     * @param output_key the key of the given output in the transaction
     * @param confirm whether the device will prompt the user to confirm their actions
     *        (to disable, must be running a DEBUG build)
     */
    generateKeyImage(tx_public_key: string, output_index: number, output_key: string, confirm?: boolean): Promise<string>;
    /**
     * Completes the given ring signature for using the supplied parameters
     * @param tx_public_key the transaction public key of the input used
     * @param output_index the index of the given output in the transaction of the input used
     * @param output_key the key of the given output in the transaction of the input used
     * @param k the random scalar returned by preparing the signatures before completion
     * @param signature the incomplete ring signature for the given input
     * @param confirm whether the device will prompt the user to confirm their actions
     *        (to disable, must be running a DEBUG build)
     */
    completeRingSignature(tx_public_key: string, output_index: number, output_key: string, k: string, signature: string, confirm?: boolean): Promise<string>;
    /**
     * Generates the ring signatures for the given inputs on the ledger device
     * without revealing the private spend key
     * @param tx_public_key the transaction public key of input being spent
     * @param output_index the index of the input being spent in the transaction
     * @param output_key the output key of the input being spent
     * @param tx_prefix_hash our transaction prefix hash
     * @param input_keys the ring participant keys (mixins + us)
     * @param real_output_index the index of the real output in the input_keys
     * @param confirm whether the device will prompt the user to confirm their actions
     *        (to disable, must be running a DEBUG build)
     */
    generateRingSignatures(tx_public_key: string, output_index: number, output_key: string, tx_prefix_hash: string, input_keys: string[], real_output_index: number, confirm?: boolean): Promise<string[]>;
    /**
     * Generates a signature of the message digest using the private spend key stored
     * on the ledger device without revealing the private spend key
     * @param message_digest the message digest (hash)
     * @param confirm whether the device will prompt the user to confirm their actions
     *        (to disable, must be running a DEBUG build)
     */
    generateSignature(message_digest: string, confirm?: boolean): Promise<string>;
    /**
     * Generates the transaction key derivation using the private view key stored
     * on the ledger device
     * @param tx_public_key the transactions public key
     * @param confirm whether the device will prompt the user to confirm their actions
     *        (to disable, must be running a DEBUG build)
     */
    generateKeyDerivation(tx_public_key: string, confirm?: boolean): Promise<string>;
    /**
     * Generates the public ephemeral of the given output in a transaction
     * @param derivation the key derivation
     * @param output_index the index of the output in the transaction
     * @param confirm whether the device will prompt the user to confirm their actions
     *        (to disable, must be running a DEBUG build)
     */
    derivePublicKey(derivation: string, output_index: number, confirm?: boolean): Promise<string>;
    /**
     * Generates the private ephemeral of the given output in a transaction
     * @param derivation the key derivation
     * @param output_index the index of the output in the transaction
     * @param confirm whether the device will prompt the user to confirm their actions
     *        (to disable, must be running a DEBUG build)
     */
    deriveSecretKey(derivation: string, output_index: number, confirm?: boolean): Promise<string>;
    /**
     * Checks a given signature using the supplied public key for validity
     * @param message_digest the message digest (hash)
     * @param public_key the public key of the private key used to sign the transaction
     * @param signature the signature to validate
     */
    checkSignature(message_digest: string, public_key: string, signature: string): Promise<boolean>;
    /**
     * Checks the ring signatures given for their validity to verify that the proper
     * private key was used for signing purposes
     * @param tx_prefix_hash the transaction prefix hash
     * @param key_image the key image spent in the input
     * @param public_keys the ring participant keys
     * @param signatures the signatures to verify
     */
    checkRingSignatures(tx_prefix_hash: string, key_image: string, public_keys: string[], signatures: string[]): Promise<boolean>;
    /**
     * Resets the keys on the ledger device the same way that they
     * are first initialized on the device
     * @param confirm
     */
    resetKeys(confirm?: boolean): Promise<void>;
    /**
     * Retrieves the current state of the transaction construction process on the ledger device
     */
    transactionState(): Promise<LedgerWalletTypes.TransactionState>;
    /**
     * Resets the transaction state of the transaction construction process on the ledger device
     */
    resetTransaction(confirm?: boolean): Promise<void>;
    /**
     * Starts a new transaction construction on the ledger device
     * @param unlock_time the unlock time (or block) of the transaction
     * @param input_count the number of inputs that will be included in the transaction
     * @param output_count the number of outputs that will be included in the transaction
     * @param tx_public_key the transaction public key
     * @param payment_id the transaction payment id if one needs to be included
     */
    startTransaction(unlock_time: number | undefined, input_count: number | undefined, output_count: number | undefined, tx_public_key: string, payment_id?: string): Promise<void>;
    /**
     * Signals to the ledger that we are ready to start loading transaction inputs
     */
    startTransactionInputLoad(): Promise<void>;
    /**
     * Load a transaction input to the transaction construction process
     * @param input_tx_public_key the transaction public key of the input
     * @param input_output_index the output index of the transaction of the input
     * @param amount the amount of the input
     * @param public_keys the ring participant keys
     * @param offsets the RELATIVE offsets of the ring participant keys
     * @param real_output_index the index in the public_keys of the real output being spent
     */
    loadTransactionInput(input_tx_public_key: string, input_output_index: number, amount: number, public_keys: string[], offsets: number[], real_output_index: number): Promise<void>;
    /**
     * Signals to the ledger that we are ready to start loading transaction outputs
     */
    startTransactionOutputLoad(): Promise<void>;
    /**
     * Load a transaction output to the transaction construction process
     * @param amount the amount of the output
     * @param output_key the output key
     */
    loadTransactionOutput(amount: number, output_key: string): Promise<void>;
    /**
     * Finalizes a transaction prefix
     */
    finalizeTransactionPrefix(): Promise<void>;
    /**
     * Instructs the ledger device to sign the transaction we have constructed
     */
    signTransaction(confirm?: boolean): Promise<{
        hash: string;
        size: number;
    }>;
    /**
     * Exports the completed full transaction that we constructed from the ledger device
     * this method requires that you keep track of what you have exported thus far as
     * we have to chunk the data due to the I/O buffer limitations of the ledger device
     * @param start_offset the starting offset
     */
    dumpTransaction(start_offset: number): Promise<Buffer>;
    /**
     * Exchanges an APDU with the connected device
     * @param command the command to send
     * @param confirm whether the device will prompt the user to confirm their actions
     *        (to disable, must be running a DEBUG build)
     * @param data any data that must be included in the payload for the given command
     */
    private exchange;
}
