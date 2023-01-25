'use strict';

var hdWallet = require('./hd-wallet.cjs');
var pow = require('./pow.cjs');
var keypair = require('./keypair.cjs');

const VEGA_ALGORITHM_NAME = 'vega/ed25519';
const VEGA_ALGORITHM_VERSION = 1;

const SLIP44_VEGA_COINTYPE = 1789;
const VEGA_DEFAULT_KEYSPACE = 0;

const VEGA_DEFAULT_PATH = [
  hdWallet.HARDENED + SLIP44_VEGA_COINTYPE,
  hdWallet.HARDENED + VEGA_DEFAULT_KEYSPACE
];

class VegaWallet extends hdWallet.HDWallet {
  constructor(...args) {
    super(...args);

    this.algorithm = {
      name: VEGA_ALGORITHM_NAME,
      version: VEGA_ALGORITHM_VERSION
    };
  }

  /**
   * @async
   * @param {Uint8Array} seed
   * @returns {Promise<VegaWallet>}
   */
  static async fromSeed (seed) {
    const master = await super.fromSeed(seed);

    const vega = await master.child(VEGA_DEFAULT_PATH[0]);
    const defaultUsage = await vega.child(VEGA_DEFAULT_PATH[1]);

    defaultUsage.id = await vega.generatePublicKey();

    return defaultUsage
  }
}

exports.HARDENED = hdWallet.HARDENED;
exports.PoW = pow;
exports.PublicKey = keypair.PublicKey;
exports.SLIP44_VEGA_COINTYPE = SLIP44_VEGA_COINTYPE;
exports.VEGA_ALGORITHM_NAME = VEGA_ALGORITHM_NAME;
exports.VEGA_ALGORITHM_VERSION = VEGA_ALGORITHM_VERSION;
exports.VEGA_DEFAULT_KEYSPACE = VEGA_DEFAULT_KEYSPACE;
exports.VEGA_DEFAULT_PATH = VEGA_DEFAULT_PATH;
exports.VegaWallet = VegaWallet;
