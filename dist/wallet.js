import { KeyPair } from './keypair.js';
import wallet from './hd.js';
import './buf-ba61d454.js';
import './crypto.js';
import 'crypto';

class Wallet {
  constructor (hd) {
    this._hd = hd;
  }

  async keyPair (index) {
    const seed = await this._hd(index);

    return KeyPair.fromSeed(index, seed)
  }

  static async fromMnemonic (mnemonic) {
    const _hd = await wallet(mnemonic);

    return new this(_hd)
  }
}

export { Wallet };
