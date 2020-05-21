// Copyright (c) 2018-2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

export {Address} from './Address';
export {AddressPrefix} from './AddressPrefix';
export {Block} from './Block';
export {BlockTemplate} from './BlockTemplate';
export {Crypto} from 'turtlecoin-crypto';
export {CryptoNote} from './CryptoNote';
export {Interfaces} from './Types/ITransaction';
export {LevinPacket, LevinProtocol} from './LevinPacket';
export {LevinPayloads} from './Types/LevinPayloads';
export {Multisig} from './Multisig';
export {MultisigMessage} from './MultisigMessage';
export {ParentBlock} from './ParentBlock';
export {Transaction} from './Transaction';
import {Crypto} from 'turtlecoin-crypto';

/** @ignore */
import * as Types from './Types';

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
export {
    KeyInput,
    KeyOutput,
    KeyPair,
    Keys,
    TransactionInputs,
    TransactionOutputs,
};

/**
 * Executes the callback method upon the given event
 * @param event
 * @param callback
 */
export function on(event: string, callback: () => void) {
    if (event.toLowerCase() === 'ready') {
        const check = () => setTimeout(() => {
            if (Crypto.isReady) {
                return callback();
            } else {
                check();
            }
        }, 100)
        check();
    }
}
