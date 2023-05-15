'use strict'

const hdWallet = require('./hd-wallet.cjs')
const pow = require('./pow.cjs')
const keypair = require('./keypair.cjs')

const SLIP44_VEGA_COINTYPE = 1789
const VEGA_DEFAULT_KEYSPACE = 0

const VEGA_DEFAULT_PATH = [
  hdWallet.HARDENED + SLIP44_VEGA_COINTYPE,
  hdWallet.HARDENED + VEGA_DEFAULT_KEYSPACE
]

class VegaWallet extends hdWallet.HDWallet {
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

exports.HARDENED = hdWallet.HARDENED
exports.PoW = pow
exports.DEFAULT_VEGA_ALGORITHM_NAME = keypair.VEGA_ALGORITHM_NAME
exports.DEFAULT_VEGA_ALGORITHM_VERSION = keypair.VEGA_ALGORITHM_VERSION
exports.PublicKey = keypair.PublicKey
exports.SLIP44_VEGA_COINTYPE = SLIP44_VEGA_COINTYPE
exports.VEGA_DEFAULT_KEYSPACE = VEGA_DEFAULT_KEYSPACE
exports.VEGA_DEFAULT_PATH = VEGA_DEFAULT_PATH
exports.VegaWallet = VegaWallet
