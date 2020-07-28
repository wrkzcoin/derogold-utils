// Copyright (c) 2018-2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

import Transport from '@ledgerhq/hw-transport';
import { Reader, Writer } from 'bytestream-helper';
import { EventEmitter } from 'events';

export namespace LedgerWalletTypes {
    /** @ignore */
    export enum APDU {
        P2 = 0x00,
        P1_NON_CONFIRM = 0x00,
        P1_CONFIRM = 0x01,
        INS = 0xe0
    }

    /**
     * Represents the APDU command types available in the TurtleCoin application
     * for ledger hardware wallets
     */
    export enum CMD {
        VERSION = 0x01,
        DEBUG = 0x02,
        IDENT = 0x05,
        PUBLIC_KEYS = 0x10,
        VIEW_SECRET_KEY = 0x11,
        SPEND_ESECRET_KEY = 0x12,
        RANDOM_KEY_PAIR = 0x19,
        ADDRESS = 0x30,
        GENERATE_KEY_IMAGE = 0x40,
        GENERATE_RING_SIGNATURES = 0x50,
        COMPLETE_RING_SIGNATURE = 0x51,
        CHECK_RING_SIGNATURES = 0x52,
        GENERATE_SIGNATURE = 0x55,
        CHECK_SIGNATURE = 0x56,
        GENERATE_KEY_DERIVATION = 0x60,
        DERIVE_PUBLIC_KEY = 0x61,
        DERIVE_SECRET_KEY = 0x62,
        RESET_KEYS = 0xff
    }

    /**
     * Represents the possible errors returned by the application
     * on the ledger device
     */
    export enum ErrorCode {
        OK = 0x9000,
        ERR_OP_NOT_PERMITTED = 0x4000,
        ERR_OP_USER_REQUIRED = 0x4001,
        ERR_UNKNOWN_ERROR = 0x4444,
        ERR_VARINT_DATA_RANGE = 0x6000,
        ERR_PRIVATE_SPEND = 0x9400,
        ERR_PRIVATE_VIEW = 0x9401,
        ERR_RESET_KEYS = 0x9402,
        ERR_ADDRESS = 0x9450,
        ERR_KEY_DERIVATION = 0x9500,
        ERR_DERIVE_PUBKEY = 0x9501,
        ERR_PUBKEY_MISMATCH = 0x9502,
        ERR_DERIVE_SECKEY = 0x9503,
        ERR_KECCAK = 0x9504,
        ERR_COMPLETE_RING_SIG = 0x9505,
        ERR_GENERATE_KEY_IMAGE = 0x9506,
        ERR_SECKEY_TO_PUBKEY = 0x9507
    }
}

/**
 * An easy to use interface that uses a Ledger HW transport to communicate with
 * the TurtleCoin application running on a ledger device.
 * Please see. See https://github.com/LedgerHQ/ledgerjs for available transport providers
 */
export class LedgerDevice extends EventEmitter {
    private readonly m_transport: Transport;

    /**
     * Creates a new instance of the Ledger interface
     * The transport MUST be connected already before passing to this constructor
     * @param transport See https://github.com/LedgerHQ/ledgerjs for available transport providers
     */
    constructor (transport: Transport) {
        super();

        this.m_transport = transport;
    }

    /**
     * Returns the underlying transport
     */
    public get transport (): Transport {
        return this.m_transport;
    }

    /**
     * Event that is emitted right before the raw bytes are sent via the APDU transport
     * @param event the event name
     * @param listener the listener function
     */
    public on(event: 'send', listener: (data: string) => void): this;

    /**
     * Emits the raw bytes received from the APDU transport in response to a request
     * @param event the event name
     * @param listener the listener function
     */
    public on(event: 'receive', listener: (data: string) => void): this;

    /** @ignore */
    public on (event: any, listener: (...args: any[]) => void): this {
        return super.on(event, listener);
    }

    /**
     * Retrieves the current version of the application running
     * on the ledger device
     */
    public async getVersion (): Promise<{ major: number, minor: number, patch: number }> {
        const result = await this.exchange(LedgerWalletTypes.CMD.VERSION);

        return {
            major: result.uint8_t().toJSNumber(),
            minor: result.uint8_t().toJSNumber(),
            patch: result.uint8_t().toJSNumber()
        };
    }

    /**
     * Returns if the application running on the ledger is a debug build
     */
    public async isDebug (): Promise<boolean> {
        const result = await this.exchange(LedgerWalletTypes.CMD.DEBUG);

        return (result.uint8_t().toJSNumber() === 1);
    }

    /**
     * Retrieves the current identification bytes of the application
     * running on the ledger device
     */
    public async getIdent (): Promise<string> {
        const result = await this.exchange(LedgerWalletTypes.CMD.IDENT);

        return result.unreadBuffer.toString('hex');
    }

    /**
     * Retrieves the public keys from the connected ledger device
     * @param confirm whether the device will prompt the user to confirm their actions (to disable, must be running a DEBUG build)
     */
    public async getPublicKeys (confirm = true): Promise<{ spend: string, view: string }> {
        const result = await this.exchange(LedgerWalletTypes.CMD.PUBLIC_KEYS, confirm);

        return {
            spend: result.hash(),
            view: result.hash()
        };
    }

    /**
     * Retrieves the private view key from the connected ledger device
     * @param confirm whether the device will prompt the user to confirm their actions (to disable, must be running a DEBUG build)
     */
    public async getPrivateViewKey (confirm = true): Promise<string> {
        const result = await this.exchange(LedgerWalletTypes.CMD.VIEW_SECRET_KEY, confirm);

        return result.hash();
    }

    /**
     * Retrieves the private spend key from the connected ledger device
     * !! WARNING !! Retrieving the private spend key from the device
     * may result in a complete loss of funds as the private spend key
     * should normally remain on the device and never leave
     *
     * @param confirm whether the device will prompt the user to confirm their actions (to disable, must be running a DEBUG build)
     */
    public async getPrivateSpendKey (confirm = true): Promise<string> {
        const result = await this.exchange(LedgerWalletTypes.CMD.SPEND_ESECRET_KEY, confirm);

        return result.hash();
    }

    /**
     * Generates a random key pair on the connected device
     */
    public async getRandomKeyPair (): Promise<{ public: string, private: string }> {
        const result = await this.exchange(LedgerWalletTypes.CMD.RANDOM_KEY_PAIR);

        return {
            public: result.hash(),
            private: result.hash()
        };
    }

    /**
     * Gets the public wallet address from the connected device
     * @param confirm whether the device will prompt the user to confirm their actions (to disable, must be running a DEBUG build)
     */
    public async getAddress (confirm = true): Promise<string> {
        const result = await this.exchange(LedgerWalletTypes.CMD.ADDRESS, confirm);

        return result.unreadBuffer.toString();
    }

    /**
     * Generates a key image on the device using the supplied parameters
     * @param tx_public_key the transaction public key
     * @param output_index the index of the given output in the transaction
     * @param output_key the key of the given output in the transaction
     * @param confirm whether the device will prompt the user to confirm their actions (to disable, must be running a DEBUG build)
     */
    public async generateKeyImage (
        tx_public_key: string,
        output_index: number,
        output_key: string,
        confirm = true
    ): Promise<string> {
        if (!isHex64(tx_public_key)) {
            throw new Error('Malformed tx_public_key supplied');
        }

        if (output_index < 0) {
            throw new Error('output_index must be >= 0');
        }

        if (!isHex64(output_key)) {
            throw new Error('Malformed output_key supplied');
        }

        const writer = new Writer();

        writer.hash(tx_public_key);

        writer.uint32_t(output_index, true);

        writer.hash(output_key);

        const result = await this.exchange(LedgerWalletTypes.CMD.GENERATE_KEY_IMAGE, confirm, writer.buffer);

        return result.hash();
    }

    /**
     * Completes the given ring signature for using the supplied parameters
     * @param tx_public_key the transaction public key of the input used
     * @param output_index the index of the given output in the transaction of the input used
     * @param output_key the key of the given output in the transaction of the input used
     * @param k the random scalar returned by preparing the signatures before completion
     * @param signature the incomplete ring signature for the given input
     * @param confirm whether the device will prompt the user to confirm their actions (to disable, must be running a DEBUG build)
     */
    public async completeRingSignature (
        tx_public_key: string,
        output_index: number,
        output_key: string,
        k: string,
        signature: string,
        confirm = true
    ): Promise<string> {
        if (!isHex64(tx_public_key)) {
            throw new Error('Malformed tx_public_key supplied');
        }

        if (output_index < 0) {
            throw new Error('output_index must be >= 0');
        }

        if (!isHex64(output_key)) {
            throw new Error('Malformed output_key supplied');
        }

        if (!isHex64(k)) {
            throw new Error('Malformed k supplied');
        }

        if (!isHex128(signature)) {
            throw new Error('Malformed signature supplied');
        }

        const writer = new Writer();

        writer.hash(tx_public_key);

        writer.uint32_t(output_index, true);

        writer.hash(output_key);

        writer.hash(k);

        writer.hex(signature);

        const result = await this.exchange(LedgerWalletTypes.CMD.COMPLETE_RING_SIGNATURE, confirm, writer.buffer);

        return result.hex(64);
    }

    /**
     * Generates the ring signatures for the given inputs on the ledger device
     * without revealing the private spend key
     * @param tx_public_key the transaction public key of input being spent
     * @param output_index the index of the input being spent in the transaction
     * @param output_key the output key of the input being spent
     * @param tx_prefix_hash our transaction prefix hash
     * @param input_keys the ring participant keys (mixins + us)
     * @param real_output_index the index of the real output in the input_keys
     * @param confirm whether the device will prompt the user to confirm their actions (to disable, must be running a DEBUG build)
     */
    public async generateRingSignatures (
        tx_public_key: string,
        output_index: number,
        output_key: string,
        tx_prefix_hash: string,
        input_keys: string[],
        real_output_index: number,
        confirm = true
    ): Promise<string[]> {
        if (!isHex64(tx_public_key)) {
            throw new Error('Malformed tx_public_key supplied');
        }

        if (output_index < 0) {
            throw new Error('output_index must be >= 0');
        }

        if (!isHex64(output_key)) {
            throw new Error('Malformed output_key supplied');
        }

        if (!isHex64(tx_prefix_hash)) {
            throw new Error('Malformed tx_prefix_hash supplied');
        }

        if (real_output_index < 0) {
            throw new Error('real_output_index must be >= 0');
        }

        if (input_keys.length === 0) {
            throw new Error('Must supply at least one input_key');
        }

        for (const key of input_keys) {
            if (!isHex64(key)) {
                throw new Error('Malformed input_key supplied');
            }
        }

        const signatures: string[] = [];

        const writer = new Writer();

        writer.hash(tx_public_key);

        writer.uint32_t(output_index, true);

        writer.hash(output_key);

        writer.hash(tx_prefix_hash);

        for (const input of input_keys) {
            writer.hash(input);
        }

        writer.uint32_t(real_output_index, true);

        const result = await this.exchange(LedgerWalletTypes.CMD.GENERATE_RING_SIGNATURES, confirm, writer.buffer);

        if (result.length % 64 !== 0) {
            throw new Error('Data returned does not appear to be a set of signatures');
        }

        while (result.unreadBytes > 0) {
            signatures.push(result.hex(64));
        }

        return signatures;
    }

    /**
     * Generates a signature of the message digest using the private spend key stored
     * on the ledger device without revealing the private spend key
     * @param message_digest the message digest (hash)
     * @param confirm whether the device will prompt the user to confirm their actions (to disable, must be running a DEBUG build)
     */
    public async generateSignature (
        message_digest: string,
        confirm = true
    ): Promise<string> {
        if (!isHex64(message_digest)) {
            throw new Error('Malformed message_digest supplied');
        }

        const writer = new Writer();

        writer.hash(message_digest);

        const result = await this.exchange(LedgerWalletTypes.CMD.GENERATE_SIGNATURE, confirm, writer.buffer);

        if (result.length !== 64) {
            throw new Error('Data returned does not appear to be a signature');
        }

        return result.hex(64);
    }

    /**
     * Generates the transaction key derivation using the private view key stored
     * on the ledger device
     * @param tx_public_key the transactions public key
     * @param confirm whether the device will prompt the user to confirm their actions (to disable, must be running a DEBUG build)
     */
    public async generateKeyDerivation (
        tx_public_key: string,
        confirm = true
    ): Promise<string> {
        if (!isHex64(tx_public_key)) {
            throw new Error('Malformed tx_public_key supplied');
        }

        const writer = new Writer();

        writer.hash(tx_public_key);

        const result = await this.exchange(LedgerWalletTypes.CMD.GENERATE_KEY_DERIVATION, confirm, writer.buffer);

        return result.hash();
    }

    /**
     * Generates the public ephemeral of the given output in a transaction
     * @param derivation the key derivation
     * @param output_index the index of the output in the transaction
     * @param confirm whether the device will prompt the user to confirm their actions (to disable, must be running a DEBUG build)
     */
    public async derivePublicKey (
        derivation: string,
        output_index: number,
        confirm = true
    ): Promise<string> {
        if (!isHex64(derivation)) {
            throw new Error('Malformed derivation supplied');
        }

        if (output_index < 0) {
            throw new Error('output_index must be >= 0');
        }

        const writer = new Writer();

        writer.hash(derivation);

        writer.uint32_t(output_index, true);

        const result = await this.exchange(LedgerWalletTypes.CMD.DERIVE_PUBLIC_KEY, confirm, writer.buffer);

        return result.hash();
    }

    /**
     * Generates the private ephemeral of the given output in a transaction
     * @param derivation the key derivation
     * @param output_index the index of the output in the transaction
     * @param confirm whether the device will prompt the user to confirm their actions (to disable, must be running a DEBUG build)
     */
    public async deriveSecretKey (
        derivation: string,
        output_index: number,
        confirm = true
    ): Promise<string> {
        if (!isHex64(derivation)) {
            throw new Error('Malformed derivation supplied');
        }

        if (output_index < 0) {
            throw new Error('output_index must be >= 0');
        }

        const writer = new Writer();

        writer.hash(derivation);

        writer.uint32_t(output_index, true);

        const result = await this.exchange(LedgerWalletTypes.CMD.DERIVE_SECRET_KEY, confirm, writer.buffer);

        return result.hash();
    }

    /**
     * Checks a given signature using the supplied public key for validity
     * @param message_digest the message digest (hash)
     * @param public_key the public key of the private key used to sign the transaction
     * @param signature the signature to validate
     */
    public async checkSignature (
        message_digest: string,
        public_key: string,
        signature: string
    ): Promise<boolean> {
        if (!isHex64(message_digest)) {
            throw new Error('Malformed message_disgest supplied');
        }

        if (!isHex64(public_key)) {
            throw new Error('Malformed public_key supplied');
        }

        if (!isHex128(signature)) {
            throw new Error('Malformed signature supplied');
        }

        const writer = new Writer();

        writer.hash(message_digest);

        writer.hash(public_key);

        writer.hex(signature);

        const result = await this.exchange(LedgerWalletTypes.CMD.CHECK_SIGNATURE, undefined, writer.buffer);

        return (result.uint8_t().toJSNumber() === 1);
    }

    /**
     * Checks the ring signatures given for their validity to verify that the proper
     * private key was used for signing purposes
     * @param tx_prefix_hash the transaction prefix hash
     * @param key_image the key image spent in the input
     * @param public_keys the ring participant keys
     * @param signatures the signatures to verify
     */
    public async checkRingSignatures (
        tx_prefix_hash: string,
        key_image: string,
        public_keys: string[],
        signatures: string[]
    ): Promise<boolean> {
        if (!isHex64(tx_prefix_hash)) {
            throw new Error('Malformed tx_prefix_hash supplied');
        }

        if (!isHex64(key_image)) {
            throw new Error('Malformed key_image supplied');
        }

        if (public_keys.length === 0) {
            throw new Error('Must supply at least one public_key');
        }

        if (signatures.length === 0) {
            throw new Error('Must supply at least one signature');
        }

        if (public_keys.length !== signatures.length) {
            throw new Error('The number of public_keys and signatures does not match');
        }

        for (const key of public_keys) {
            if (!isHex64(key)) {
                throw new Error('Malformed public_key supplied');
            }
        }

        for (const sig of signatures) {
            if (!isHex128(sig)) {
                throw new Error('Malformed signature supplied');
            }
        }

        const writer = new Writer();

        writer.hash(tx_prefix_hash);

        writer.hash(key_image);

        for (const key of public_keys) {
            writer.hash(key);
        }

        for (const sig of signatures) {
            writer.hex(sig);
        }

        const result = await this.exchange(LedgerWalletTypes.CMD.CHECK_RING_SIGNATURES, undefined, writer.buffer);

        return (result.uint8_t().toJSNumber() === 1);
    }

    /**
     * Resets the keys on the ledger device the same way that they
     * are first initialized on the device
     * @param confirm
     */
    public async resetKeys (
        confirm = true
    ): Promise<void> {
        await this.exchange(LedgerWalletTypes.CMD.RESET_KEYS, confirm);
    }

    /**
     * Exchanges an APDU with the connected device
     * @param command the command to send
     * @param confirm whether the device will prompt the user to confirm their actions (to disable, must be running a DEBUG build)
     * @param data any data that must be included in the payload for the given command
     */
    private async exchange (command: LedgerWalletTypes.CMD, confirm = true, data?: Buffer): Promise<Reader> {
        const writer = new Writer();

        writer.uint8_t(LedgerWalletTypes.APDU.INS);

        writer.uint8_t(command);

        if (confirm) {
            writer.uint8_t(LedgerWalletTypes.APDU.P1_CONFIRM);
        } else {
            writer.uint8_t(LedgerWalletTypes.APDU.P1_NON_CONFIRM);
        }

        writer.uint8_t(LedgerWalletTypes.APDU.P2);

        if (data) {
            if (data.length > (512 - 6)) {
                throw new Error('Data payload exceeds maximum size');
            }

            writer.uint16_t(data.length, true);

            writer.write(data);
        } else {
            writer.uint16_t(0);
        }

        this.emit('send', writer.blob);

        const result = await this.m_transport.exchange(writer.buffer);

        this.emit('receive', (new Reader(result)).unreadBuffer.toString('hex'));

        const code = result.slice(result.length - 2);

        const response = new Reader(result.slice(0, result.length - code.length));

        const reader = new Reader(code);

        let errCode = reader.uint16_t(true).toJSNumber();

        if (errCode !== LedgerWalletTypes.ErrorCode.OK) {
            if (response.length >= 2) {
                errCode = response.uint16_t(true).toJSNumber();
            }

            throw new Error('Could not complete request: ' + errCode);
        }

        return response;
    }
}

/**
 * @ignore
 */
function isHex (value: string): boolean {
    if (value.length % 2 !== 0) {
        return false;
    }

    const regex = new RegExp('^[0-9a-fA-F]{' + value.length + '}$');

    return regex.test(value);
}

/**
 * @ignore
 */
function isHex64 (value: string): boolean {
    return (isHex(value) && value.length === 64);
}

/**
 * @ignore
 */
function isHex128 (value: string): boolean {
    return (isHex(value) && value.length === 128);
}
