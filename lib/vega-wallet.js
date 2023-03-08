import { HDWallet, HARDENED } from './hd-wallet.js'
import * as PoW from './pow.js'

export {
  VEGA_ALGORITHM_NAME as DEFAULT_VEGA_ALGORITHM_NAME,
  VEGA_ALGORITHM_VERSION as DEFAULT_VEGA_ALGORITHM_VERSION,
  PublicKey
} from './keypair.js'
export { HARDENED, PoW }

export const SLIP44_VEGA_COINTYPE = 1789
export const VEGA_DEFAULT_KEYSPACE = 0

export const VEGA_DEFAULT_PATH = [
  HARDENED + SLIP44_VEGA_COINTYPE,
  HARDENED + VEGA_DEFAULT_KEYSPACE
]

export class VegaWallet extends HDWallet {
  /**
   * @async
   * @param {Uint8Array} seed
   * @returns {Promise<VegaWallet>}
   */
  static async fromSeed (seed) {
    const master = await super.fromSeed(seed)

    const vega = await master.child(VEGA_DEFAULT_PATH[0])
    const defaultUsage = await vega.child(VEGA_DEFAULT_PATH[1])

    defaultUsage.id = await vega.generatePublicKey()

    return defaultUsage
  }
}
