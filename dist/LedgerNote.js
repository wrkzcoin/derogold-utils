"use strict";
// Copyright (c) 2018-2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LedgerNote = void 0;
const LedgerDevice_1 = require("./LedgerDevice");
const Types_1 = require("./Types");
const Common_1 = require("./Common");
const AddressPrefix_1 = require("./AddressPrefix");
const Address_1 = require("./Address");
const Numeral = require("numeral");
var TransactionState = Types_1.LedgerTypes.TransactionState;
var KeyPair = Types_1.ED25519.KeyPair;
/** @ignore */
const Config = require('../config.json');
/** @ignore */
const NULL_KEY = ''.padEnd(64, '0');
/** @ignore */
const UINT64_MAX = Types_1.BigInteger(2).pow(64);
class LedgerNote {
    /**
     * Constructs a new instance of the Ledger-based CryptoNote tools
     * @param transport the transport mechanism for talking to a Ledger device
     * @param config [config] the base configuration to apply to our helper
     */
    constructor(transport, config) {
        this.config = require('../config.json');
        this.m_spend = new KeyPair();
        this.m_view = new KeyPair();
        this.m_address = new Address_1.Address();
        this.m_fetched = false;
        this.m_ledger = new LedgerDevice_1.LedgerDevice(transport);
        if (config) {
            Object.keys(config).forEach((key) => {
                switch (key) {
                    case 'coinUnitPlaces':
                        this.config.coinUnitPlaces = config[key];
                        break;
                    case 'addressPrefix':
                        this.config.addressPrefix = config[key];
                        break;
                    case 'keccakIterations':
                        this.config.keccakIterations = config[key];
                        break;
                    case 'defaultNetworkFee':
                        this.config.defaultNetworkFee = config[key];
                        break;
                    case 'fusionMinInputCount':
                        this.config.fusionMinInputCount = config[key];
                        break;
                    case 'fusionMinInOutCountRatio':
                        this.config.fusionMinInOutCountRatio = config[key];
                        break;
                    case 'mmMiningBlockVersion':
                        this.config.mmMiningBlockVersion = config[key];
                        break;
                    case 'maximumOutputAmount':
                        this.config.maximumOutputAmount = config[key];
                        break;
                    case 'maximumOutputsPerTransaction':
                        this.config.maximumOutputsPerTransaction = config[key];
                        break;
                    case 'maximumExtraSize':
                        this.config.maximumExtraSize = config[key];
                        break;
                    case 'activateFeePerByteTransactions':
                        this.config.activateFeePerByteTransactions = config[key];
                        break;
                    case 'feePerByte':
                        this.config.feePerByte = config[key];
                        break;
                    case 'feePerByteChunkSize':
                        this.config.feePerByteChunkSize = config[key];
                        break;
                }
            });
            Types_1.TurtleCoinCrypto.userCryptoFunctions = config;
        }
    }
    /**
     * Provides the public wallet address of the ledger device
     */
    get address() {
        if (!this.ready) {
            throw new Error('Instance is not ready');
        }
        return this.m_address;
    }
    /**
     * Fetches the public keys and private view key from the Ledger device
     * and stores it locally for use later
     */
    fetchKeys() {
        return __awaiter(this, void 0, void 0, function* () {
            const keys = yield this.m_ledger.getPublicKeys();
            this.m_spend = keys.spend;
            this.m_view = keys.view;
            const view = yield this.m_ledger.getPrivateViewKey();
            yield this.m_view.setPrivateKey(view.privateKey);
            const prefix = new AddressPrefix_1.AddressPrefix(this.config.addressPrefix || Config.addressPrefix);
            this.m_address = yield Address_1.Address.fromPublicKeys(keys.spend.publicKey, keys.view.publicKey, undefined, prefix);
            this.m_fetched = true;
        });
    }
    /**
     * Indicates whether the keys have been fetched from the ledger device
     * and this instance of the class is ready for further interaction
     */
    get ready() {
        return this.m_fetched;
    }
    /**
     * Converts absolute global index offsets to relative ones
     * @param offsets the absolute offsets
     * @returns the relative offsets
     */
    absoluteToRelativeOffsets(offsets) {
        const result = [];
        const tmpOffsets = Common_1.Common.absoluteToRelativeOffsets(offsets);
        tmpOffsets.forEach((offset) => result.push(offset.toJSNumber()));
        return result;
    }
    /**
     * Converts relative global index offsets to absolute offsets
     * @param offsets the relative offsets
     * @returns the absolute offsets
     */
    relativeToAbsoluteOffsets(offsets) {
        const result = [];
        const tmpOffsets = Common_1.Common.relativeToAbsoluteOffsets(offsets);
        tmpOffsets.forEach((offset) => result.push(offset.toJSNumber()));
        return result;
    }
    /**
     * Generates a key image from the supplied values
     * @async
     * @param transactionPublicKey the transaction public key
     * @param privateViewKey the private view key
     * @param publicSpendKey the public spend key
     * @param privateSpendKey the private spend key
     * @param outputIndex the index of the output in the transaction
     * @returns the key image
     */
    generateKeyImage(transactionPublicKey, privateViewKey, publicSpendKey, privateSpendKey, outputIndex) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.ready) {
                yield this.fetchKeys();
            }
            UNUSED(privateViewKey);
            UNUSED(publicSpendKey);
            UNUSED(privateSpendKey);
            const derivation = yield Types_1.TurtleCoinCrypto.generateKeyDerivation(transactionPublicKey, this.m_view.privateKey);
            return this.generateKeyImagePrimitive(undefined, undefined, outputIndex, derivation);
        });
    }
    /**
     * Primitive method for generating a key image from the supplied values
     * @async
     * @param publicSpendKey the public spend key
     * @param privateSpendKey the private spend key
     * @param outputIndex the index of the output in the transaction
     * @param derivation the key derivation
     * @returns the key image
     */
    generateKeyImagePrimitive(publicSpendKey, privateSpendKey, outputIndex, derivation) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.ready) {
                yield this.fetchKeys();
            }
            UNUSED(publicSpendKey);
            UNUSED(privateSpendKey);
            const publicEphemeral = yield Types_1.TurtleCoinCrypto.derivePublicKey(derivation, outputIndex, this.m_spend.publicKey);
            const result = yield this.m_ledger.generateKeyImagePrimitive(derivation, outputIndex, publicEphemeral);
            return {
                publicEphemeral: publicEphemeral,
                keyImage: result
            };
        });
    }
    /**
     * Provides the public key of the supplied private key
     * @async
     * @param privateKey the private key
     * @returns the public key
     */
    privateKeyToPublicKey(privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            return Types_1.TurtleCoinCrypto.secretKeyToPublicKey(privateKey);
        });
    }
    /**
     * Scans the provided transaction outputs and returns those outputs which belong to us.
     * If the privateSpendKey is not supplied, the private ephemeral and key image will be undefined
     * @async
     * @param transactionPublicKey the transaction public key
     * @param outputs the transaction outputs
     * @param privateViewKey the private view key
     * @param publicSpendKey the public spend key
     * @param [privateSpendKey] the private spend key
     * @param [generatePartial] whether we should generate partial key images if the output belongs to use
     * @returns an list of outputs that belong to us
     */
    scanTransactionOutputs(transactionPublicKey, outputs, privateViewKey, publicSpendKey, privateSpendKey, generatePartial) {
        return __awaiter(this, void 0, void 0, function* () {
            const promises = [];
            for (const output of outputs) {
                promises.push(this.isOurTransactionOutput(transactionPublicKey, output, privateViewKey, publicSpendKey, privateSpendKey, generatePartial).catch());
            }
            const results = yield Promise.all(promises);
            const ourOutputs = [];
            for (const result of results) {
                if (result) {
                    ourOutputs.push(result);
                }
            }
            return ourOutputs;
        });
    }
    /**
     * Scans the given transaction output to determine if it belongs to us, if so, we return the output
     * with the private ephemeral and key image if the privateSpendKey was supplied
     * @async
     * @param transactionPublicKey the transaction public key
     * @param output the transaction output
     * @param privateViewKey the private view key
     * @param publicSpendKey the public spend key
     * @param [privateSpendKey] the private spend key
     * @param [generatePartial] whether we should generate partial key images
     * @returns the output if it belongs to us
     */
    isOurTransactionOutput(transactionPublicKey, output, privateViewKey, publicSpendKey, privateSpendKey, generatePartial = false) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.ready) {
                yield this.fetchKeys();
            }
            if (generatePartial) {
                throw new Error('Generating partial key images is not supported');
            }
            UNUSED(privateViewKey);
            UNUSED(publicSpendKey);
            UNUSED(privateSpendKey);
            const derivedKey = yield Types_1.TurtleCoinCrypto.generateKeyDerivation(transactionPublicKey, this.m_view.privateKey);
            const publicEphemeral = yield Types_1.TurtleCoinCrypto.derivePublicKey(derivedKey, output.index, this.m_spend.publicKey);
            if (publicEphemeral === output.key) {
                output.input = {
                    publicEphemeral,
                    transactionKeys: {
                        publicKey: transactionPublicKey,
                        derivedKey,
                        outputIndex: output.index
                    }
                };
                const result = yield this.generateKeyImage(transactionPublicKey, undefined, undefined, undefined, output.index);
                // we don't store this as it is private
                output.input.privateEphemeral = NULL_KEY;
                output.keyImage = result.keyImage;
                return output;
            }
            throw new Error('Not our output');
        });
    }
    /**
     * Calculates the minimum transaction fee given the transaction size (bytes)
     * @param txSize the transaction size in bytes
     * @returns the minimum transaction fee
     */
    calculateMinimumTransactionFee(txSize) {
        const chunks = Math.ceil(txSize /
            (this.config.feePerByteChunkSize || Config.feePerByteChunkSize));
        return chunks *
            (this.config.feePerByteChunkSize || Config.feePerByteChunkSize) *
            (this.config.feePerByte || Config.feePerByte);
    }
    /**
     * Creates an integrated address using the supplied values
     * @param address the wallet address
     * @param paymentId the payment ID
     * @param [prefix] the address prefix
     * @returns the integrated address
     */
    createIntegratedAddress(address, paymentId, prefix) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof prefix === 'number') {
                prefix = new AddressPrefix_1.AddressPrefix(prefix);
            }
            if (!prefix) {
                prefix = new AddressPrefix_1.AddressPrefix(this.config.addressPrefix || Config.addressPrefix);
            }
            const addr = yield Address_1.Address.fromAddress(address);
            addr.paymentId = paymentId;
            if (prefix) {
                addr.prefix = prefix;
            }
            return addr.toString();
        });
    }
    /**
     * Formats atomic units into human readable units
     * @param amount the amount in atomic units
     * @returns the amount in human readable units
     */
    formatMoney(amount) {
        let places = '';
        for (let i = 0; i < (this.config.coinUnitPlaces || Config.coinUnitPlaces); i++) {
            places += '0';
        }
        if (typeof amount !== 'number') {
            amount = amount.toJSNumber();
        }
        return Numeral(amount / Math.pow(10, this.config.coinUnitPlaces || Config.coinUnitPlaces)).format('0,0.' + places);
    }
    /**
     * Generates an array of transaction outputs (new destinations) for the given address
     * and the given amount within the allowed rules of the network
     * @param address the destination wallet address
     * @param amount the amount to send
     * @returns a list of transaction outputs
     */
    generateTransactionOutputs(address, amount) {
        return __awaiter(this, void 0, void 0, function* () {
            if (amount < 0) {
                throw new RangeError('Amount must be a positive value');
            }
            const result = [];
            const destination = yield Address_1.Address.fromAddress(address);
            const amountChars = amount.toString().split('').reverse();
            for (let i = 0; i < amountChars.length; i++) {
                const amt = parseInt(amountChars[i], 10) * Math.pow(10, i);
                if (amt > (this.config.maximumOutputAmount || Config.maximumOutputAmount)) {
                    let splitAmt = amt;
                    while (splitAmt >= (this.config.maximumOutputAmount || Config.maximumOutputAmount)) {
                        result.push({
                            amount: this.config.maximumOutputAmount || Config.maximumOutputAmount,
                            destination: destination
                        });
                        splitAmt -= this.config.maximumOutputAmount || Config.maximumOutputAmount;
                    }
                }
                else if (amt !== 0) {
                    result.push({
                        amount: amt,
                        destination: destination
                    });
                }
            }
            return result;
        });
    }
    /**
     * Signs an arbitrary message using the supplied private key
     * @async
     * @param message the arbitrary message to sign
     * @param privateKey the private key to sign with
     * @returns the signature
     */
    signMessage(message, privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            UNUSED(privateKey);
            if (typeof message !== 'string') {
                message = JSON.stringify(message);
            }
            const hex = Buffer.from(message);
            const hash = yield Types_1.TurtleCoinCrypto.cn_fast_hash(hex.toString('hex'));
            return this.m_ledger.generateSignature(hash);
        });
    }
    /**
     * Verifies the signature of an arbitrary message using the signature and the supplied public key
     * @async
     * @param message the arbitrary message that was signed
     * @param publicKey the public key of the private key that was used to sign
     * @param signature the signature
     * @returns whether the signature is valid
     */
    verifyMessageSignature(message, publicKey, signature) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof message !== 'string') {
                message = JSON.stringify(message);
            }
            const hex = Buffer.from(message);
            const hash = yield Types_1.TurtleCoinCrypto.cn_fast_hash(hex.toString('hex'));
            return Types_1.TurtleCoinCrypto.checkSignature(hash, publicKey, signature);
        });
    }
    /**
     * Constructs a new Transaction using the supplied values.
     * Note: Does not sign the transaction
     * @async
     * @param outputs the new outputs for the transaction (TO)
     * @param inputs outputs we will be spending (FROM)
     * @param randomOutputs the random outputs to use for mixing
     * @param mixin the number of mixins to use
     * @param [feeAmount] the transaction fee amount to pay
     * @param [paymentId] the payment ID to use in the transaction,
     * @param [unlockTime] the unlock time or block height for the transaction
     * @param [extraData] arbitrary extra data to include in the transaction extra field
     * @returns the newly created transaction object and it's input data
     */
    createTransaction(outputs, inputs, randomOutputs, mixin, feeAmount, paymentId, unlockTime, extraData) {
        return __awaiter(this, void 0, void 0, function* () {
            if (extraData) {
                throw new Error('Supplying extra transaction data is not supported');
            }
            if (typeof feeAmount === 'undefined') {
                feeAmount = this.config.defaultNetworkFee || Config.defaultNetworkFee;
            }
            unlockTime = unlockTime || 0;
            const feePerByte = this.config.activateFeePerByteTransactions || Config.activateFeePerByteTransactions || false;
            if (randomOutputs.length !== inputs.length && mixin !== 0) {
                throw new Error('The sets of random outputs supplied does not match the number of inputs supplied');
            }
            for (const randomOutput of randomOutputs) {
                if (randomOutput.length < mixin) {
                    throw new Error('There are not enough random outputs to mix with');
                }
            }
            let neededMoney = Types_1.BigInteger.zero;
            let integratedPaymentId;
            for (const output of outputs) {
                if (output.amount <= 0) {
                    throw new RangeError('Cannot create an output with an amount <= 0');
                }
                if (output.amount > (this.config.maximumOutputAmount || Config.maximumOutputAmount)) {
                    throw new RangeError('Cannot create an output with an amount > ' +
                        (this.config.maximumOutputAmount || Config.maximumOutputAmount));
                }
                neededMoney = neededMoney.add(output.amount);
                if (neededMoney.greater(UINT64_MAX)) {
                    throw new RangeError('Total output amount exceeds UINT64_MAX');
                }
                /* Check to see if our destination contains differeing payment IDs via integrated addresses */
                if (output.destination.paymentId) {
                    if (!integratedPaymentId) {
                        integratedPaymentId = output.destination.paymentId;
                    }
                    else if (integratedPaymentId && integratedPaymentId !== output.destination.paymentId) {
                        throw new Error('Cannot perform multiple transfers with differing integrated addresses');
                    }
                }
            }
            /* If we found an integrated payment ID in the destinations and we supplied a payment ID
            in our call to this method and they do not match, this will result in a failure */
            if (integratedPaymentId && paymentId && integratedPaymentId !== paymentId) {
                throw new Error('Transfer destinations contains an integrated payment ID that does not match the payment' +
                    'ID supplied to this method');
            }
            let foundMoney = Types_1.BigInteger.zero;
            for (const input of inputs) {
                if (input.amount <= 0) {
                    throw new RangeError('Cannot spend outputs with an amount <= 0');
                }
                foundMoney = foundMoney.add(input.amount);
                if (foundMoney.greater(UINT64_MAX)) {
                    throw new RangeError('Total input amount exceeds UINT64_MAX');
                }
            }
            if (neededMoney.greater(foundMoney)) {
                throw new Error('We need more funds than was currently supplied for the transaction');
            }
            const change = foundMoney.subtract(neededMoney);
            if (!feePerByte && feeAmount && change.lesser(feeAmount)) {
                throw new Error('We have not spent all of what we sent in');
            }
            const transactionInputs = yield prepareTransactionInputs(inputs, randomOutputs, mixin);
            // Use the ledger to get our random pair of keys for the one-time transaction keys
            const tx_keys = yield this.m_ledger.getRandomKeyPair();
            const transactionOutputs = yield prepareTransactionOutputs(tx_keys, outputs);
            if (transactionOutputs.outputs.length >
                (this.config.maximumOutputsPerTransaction || Config.maximumOutputsPerTransaction)) {
                throw new RangeError('Tried to create a transaction with more outputs than permitted');
            }
            if (feeAmount === 0) {
                if (transactionInputs.length < 12) {
                    throw new Error('Sending a [0] fee transaction (fusion) requires a minimum of [' +
                        (this.config.fusionMinInputCount || Config.fusionMinInputCount) + '] inputs');
                }
                const ratio = this.config.fusionMinInOutCountRatio || Config.fusionMinInOutCountRatio;
                if ((transactionInputs.length / transactionOutputs.outputs.length) < ratio) {
                    throw new Error('Sending a [0] fee transaction (fusion) requires the ' +
                        'correct input:output ratio be met');
                }
            }
            transactionInputs.sort((a, b) => {
                return (Types_1.BigInteger(a.keyImage, 16).compare(Types_1.BigInteger(b.keyImage, 16)) * -1);
            });
            try {
                yield this.m_ledger.startTransaction(unlockTime, transactionInputs.length, transactionOutputs.outputs.length, tx_keys.publicKey, paymentId || undefined);
                if ((yield this.m_ledger.transactionState()) !== TransactionState.READY) {
                    throw new Error('Ledger transaction construction not ready.');
                }
                yield this.m_ledger.startTransactionInputLoad();
                if ((yield this.m_ledger.transactionState()) !== TransactionState.RECEIVING_INPUTS) {
                    throw new Error('Ledger is not ready to receive inputs.');
                }
                for (const input of transactionInputs) {
                    let offsets = input.outputs
                        .map(output => Types_1.BigInteger(output.index));
                    offsets = Common_1.Common.absoluteToRelativeOffsets(offsets)
                        .map(offset => offset.toJSNumber());
                    yield this.m_ledger.loadTransactionInput(input.input.transactionKeys.publicKey, input.input.transactionKeys.outputIndex, input.amount, input.outputs.map(elem => elem.key), offsets, input.realOutputIndex);
                }
                if ((yield this.m_ledger.transactionState()) !== TransactionState.INPUTS_RECEIVED) {
                    throw new Error('Ledger did not receive all required inputs.');
                }
                yield this.m_ledger.startTransactionOutputLoad();
                if ((yield this.m_ledger.transactionState()) !== TransactionState.RECEIVING_OUTPUTS) {
                    throw new Error('Ledger is not ready to receive outputs.');
                }
                for (const output of transactionOutputs.outputs) {
                    yield this.m_ledger.loadTransactionOutput(output.amount, output.key);
                }
                if ((yield this.m_ledger.transactionState()) !== TransactionState.OUTPUTS_RECEIVED) {
                    throw new Error('Ledger did not receive all required outputs.');
                }
                yield this.m_ledger.finalizeTransactionPrefix();
                if ((yield this.m_ledger.transactionState()) !== TransactionState.PREFIX_READY) {
                    throw new Error('Ledger did not properly finalize the transaction prefix.');
                }
                const result = yield this.m_ledger.signTransaction();
                if ((yield this.m_ledger.transactionState()) !== TransactionState.COMPLETE) {
                    throw new Error('Ledger did not properly complete the transaction.');
                }
                const tx = yield this.m_ledger.retrieveTransaction();
                if ((yield tx.hash()) !== result.hash) {
                    throw new Error('Transaction hash mismatch');
                }
                if (tx.size !== result.size) {
                    throw new Error('Transaction size mismatch');
                }
                return tx;
            }
            finally {
                yield this.m_ledger.resetTransaction();
            }
        });
    }
    /**
     * Constructs a new Transaction using the supplied values.
     * Note: Does not sign the transaction
     * @async
     * @param outputs the new outputs for the transaction (TO)
     * @param inputs outputs we will be spending (FROM)
     * @param randomOutputs the random outputs to use for mixing
     * @param mixin the number of mixins to use
     * @param [feeAmount] the transaction fee amount to pay
     * @param [paymentId] the payment ID to use in the transaction,
     * @param [unlockTime] the unlock time or block height for the transaction
     * @param [extraData] arbitrary extra data to include in the transaction extra field
     * @returns the newly created transaction object and it's input data
     */
    createTransactionStructure(outputs, inputs, randomOutputs, mixin, feeAmount, paymentId, unlockTime, extraData) {
        return __awaiter(this, void 0, void 0, function* () {
            UNUSED(outputs);
            UNUSED(inputs);
            UNUSED(randomOutputs);
            UNUSED(mixin);
            UNUSED(feeAmount);
            UNUSED(paymentId);
            UNUSED(unlockTime);
            UNUSED(extraData);
            throw new Error('Not implemented');
        });
    }
    /**
     * Constructs a new Transaction using the supplied values.
     * The resulting transaction can be broadcasted to the TurtleCoin network
     * @async
     * @param outputs the new outputs for the transaction (TO)
     * @param inputs outputs we will be spending (FROM)
     * @param randomOutputs the random outputs to use for mixing
     * @param mixin the number of mixins to use
     * @param [feeAmount] the transaction fee amount to pay
     * @param [paymentId] the payment ID to use in the transaction,
     * @param [unlockTime] the unlock time or block height for the transaction
     * @param [extraData] arbitrary extra data to include in the transaction extra field
     * @param [randomKey] a random scalar (private key)
     * @returns the newly created transaction object with prepared signatures
     */
    prepareTransaction(outputs, inputs, randomOutputs, mixin, feeAmount, paymentId, unlockTime, extraData, randomKey) {
        return __awaiter(this, void 0, void 0, function* () {
            UNUSED(outputs);
            UNUSED(inputs);
            UNUSED(randomOutputs);
            UNUSED(mixin);
            UNUSED(feeAmount);
            UNUSED(paymentId);
            UNUSED(unlockTime);
            UNUSED(extraData);
            UNUSED(randomKey);
            throw new Error('Not implemented');
        });
    }
    /**
     * Completes a prepared transaction using the supplied private ephemeral
     * The resulting transaction can be broadcast to the network. Please note that the PreparedTransaction
     * signatures meta data must be updated to include the proper private ephemeral
     * @param preparedTransaction the prepared transaction
     * @param privateSpendKey the private spend key of the wallet that contains the funds
     * @returns the completed transaction
     */
    completeTransaction(preparedTransaction, privateSpendKey) {
        return __awaiter(this, void 0, void 0, function* () {
            UNUSED(preparedTransaction);
            UNUSED(privateSpendKey);
            throw new Error('Not implemented');
        });
    }
}
exports.LedgerNote = LedgerNote;
/** @ignore */
function UNUSED(val) {
    return val || NULL_KEY;
}
/** @ignore */
function prepareTransactionInputs(inputs, randomOutputs, mixin) {
    if (inputs.length !== randomOutputs.length && mixin !== 0) {
        throw new Error('There are not enough random output sets to mix with the real outputs');
    }
    for (const randomOutput of randomOutputs) {
        if (randomOutput.length < mixin) {
            throw new Error('There are not enough random outputs to mix with');
        }
    }
    const mixedInputs = [];
    for (let i = 0; i < inputs.length; i++) {
        const mixedOutputs = [];
        const realOutput = inputs[i];
        if (!realOutput.keyImage) {
            throw new Error('input is missing its key image');
        }
        if (!realOutput.input) {
            throw new Error('input is missing mandatory data fields');
        }
        if (realOutput.amount <= 0) {
            throw new RangeError('Real inputs cannot have an amount <= 0');
        }
        if (mixin !== 0) {
            const fakeOutputs = randomOutputs[i];
            fakeOutputs.sort((a, b) => {
                return Types_1.BigInteger(a.globalIndex).compare(b.globalIndex);
            });
            for (const fakeOutput of fakeOutputs) {
                if (mixedOutputs.length === mixin) {
                    continue;
                }
                if (fakeOutput.globalIndex === realOutput.globalIndex) {
                    continue;
                }
                mixedOutputs.push({
                    key: fakeOutput.key,
                    index: fakeOutput.globalIndex
                });
            }
            if (mixedOutputs.length < mixin) {
                throw new Error('It is impossible to mix with yourself. Find some more random outputs and try again.');
            }
        }
        mixedOutputs.push({
            key: realOutput.key,
            index: realOutput.globalIndex
        });
        mixedOutputs.sort((a, b) => {
            return Types_1.BigInteger(a.index).compare(b.index);
        });
        const input = {
            amount: realOutput.amount,
            realOutputIndex: 0,
            keyImage: realOutput.keyImage,
            input: realOutput.input,
            outputs: mixedOutputs
        };
        for (let j = 0; j < mixedOutputs.length; j++) {
            if (mixedOutputs[j].index === realOutput.globalIndex) {
                input.realOutputIndex = j;
            }
        }
        mixedInputs.push(input);
    }
    return mixedInputs;
}
/** @ignore */
function prepareTransactionOutputs(transactionKeys, outputs) {
    return __awaiter(this, void 0, void 0, function* () {
        function prepareOutput(destination, amount, index, privateKey) {
            return __awaiter(this, void 0, void 0, function* () {
                const outDerivation = yield Types_1.TurtleCoinCrypto.generateKeyDerivation(destination.view.publicKey, privateKey);
                const outPublicEphemeral = yield Types_1.TurtleCoinCrypto.derivePublicKey(outDerivation, index, destination.spend.publicKey);
                return {
                    amount,
                    key: outPublicEphemeral
                };
            });
        }
        outputs.sort((a, b) => (a.amount > b.amount) ? 1 : ((b.amount > a.amount) ? -1 : 0));
        const promises = [];
        for (let i = 0; i < outputs.length; i++) {
            const output = outputs[i];
            if (output.amount <= 0) {
                throw new RangeError('Amount cannot be <= 0');
            }
            promises.push(prepareOutput(output.destination, output.amount, i, transactionKeys.privateKey));
        }
        const preparedOutputs = yield Promise.all(promises);
        return {
            transactionKeys,
            outputs: preparedOutputs
        };
    });
}
