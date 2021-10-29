import { KeyPair } from './keypair.mjs'
import hd from './hd.mjs'

export class Wallet {
  constructor (hd) {
    this._hd = hd
  }

  async keyPair (index) {
    const seed = await this._hd(index)

    return KeyPair.fromSeed(index, seed)
  }

  static async fromMnemonic (mnemonic) {
    const _hd = await hd(mnemonic)

    return new this(_hd)
  }
}
