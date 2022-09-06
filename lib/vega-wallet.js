import { Wallet, HARDENED } from './hd-wallet.js'
import * as PoW from './pow.js'

export { PublicKey } from './keypair.js'
export { HARDENED, PoW }

export const SLIP44_VEGA_COINTYPE = 1789
export const VEGA_DEFAULT_KEYSPACE = 0

export class VegaWallet extends Wallet {
  /**
   * @param {string | Uint8Array} mnemonic
   */
  static async fromMnemonic (mnemonic) {
    const master = await super.fromMnemonic(mnemonic)
    const vega = await master.child(HARDENED + SLIP44_VEGA_COINTYPE)
    const defaultUsage = await vega.child(HARDENED + VEGA_DEFAULT_KEYSPACE)

    return defaultUsage
  }
}
