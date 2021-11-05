import { Wallet, HARDENED } from './hd-wallet'
export { HARDENED } from './hd-wallet'
export { PublicKey } from './keypair'

export const SLIP44_VEGA_COINTYPE = 1789
export const VEGA_DEFAULT_KEYSPACE = 0

export class VegaWallet extends Wallet {
  static async fromMnemonic (mnemonic) {
    const master = await super.fromMnemonic(mnemonic)
    const vega = await master.child(HARDENED + SLIP44_VEGA_COINTYPE)
    const defaultUsage = await vega.child(HARDENED + VEGA_DEFAULT_KEYSPACE)

    return defaultUsage
  }
}
