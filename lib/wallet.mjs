import { Wallet, HARDENED } from './hd-wallet'
export { HARDENED } from './hd-wallet'

export class VegaWallet extends Wallet {
  static async fromMnemonic (mnemonic) {
    const master = await super.fromMnemonic(mnemonic)
    const vega = await master.child(HARDENED + 1789)
    const defaultUsage = await vega.child(HARDENED + 0)

    return defaultUsage
  }
}
