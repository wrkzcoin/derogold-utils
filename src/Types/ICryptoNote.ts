// Copyright (c) 2018-2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

export namespace CryptoNoteInterfaces {
    export interface IKeyImage {
        keyImage: string;
        publicEphemeral: string;
        privateEphemeral: string;
    }
}
