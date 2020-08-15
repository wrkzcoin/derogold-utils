// Copyright (c) 2018-2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

import { Crypto } from 'turtlecoin-crypto';

/** @ignore */
import * as Types from './Types';
export { Address } from './Address';
export { AddressPrefix } from './AddressPrefix';
export { Block } from './Block';
export { BlockTemplate } from './BlockTemplate';
export { Crypto, ICryptoConfig } from 'turtlecoin-crypto';
export { CryptoNote } from './CryptoNote';
export { Interfaces } from './Types/ITransaction';
export { LedgerDevice, LedgerTransport } from './LedgerDevice';
export { LedgerNote } from './LedgerNote';
export { LevinPacket, LevinProtocol } from './LevinPacket';
export { LevinPayloads } from './Types/LevinPayloads';
export { Multisig } from './Multisig';
export { MultisigMessage } from './MultisigMessage';
export { ParentBlock } from './ParentBlock';
export { Transaction } from './Transaction';
export { ICoinConfig } from './Config';

/** @ignore */
import TransactionOutputs = Types.TransactionOutputs;
/** @ignore */
import TransactionInputs = Types.TransactionInputs;
/** @ignore */
import KeyInput = TransactionInputs.KeyInput;
/** @ignore */
import KeyOutput = TransactionOutputs.KeyOutput;
/** @ignore */
import KeyPair = Types.ED25519.KeyPair;
/** @ignore */
import Keys = Types.ED25519.Keys;
/** @ignore */
import LedgerError = Types.LedgerTypes.LedgerError;
/** @ignore */
import LedgerTransactionState = Types.LedgerTypes.TransactionState;
/** @ignore */
import LedgerErrorCode = Types.LedgerTypes.ErrorCode;
/** @ignore */
import ICryptoNote = Types.CryptoNoteInterfaces.ICryptoNote;

/** @ignore */
export {
    ICryptoNote,
    KeyInput,
    KeyOutput,
    KeyPair,
    Keys,
    TransactionInputs,
    TransactionOutputs,
    LedgerError,
    LedgerTransactionState,
    LedgerErrorCode
};

/**
 * Executes the callback method upon the given event
 * @param event
 * @param callback
 */
export function on (event: string, callback: () => void) {
    if (event.toLowerCase() === 'ready') {
        const check = () => setTimeout(() => {
            if (Crypto.isReady) {
                return callback();
            } else {
                check();
            }
        }, 100);
        check();
    }
}
