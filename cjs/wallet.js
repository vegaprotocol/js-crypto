'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var hdWallet = require('./hd-wallet.js');
var keypair = require('./keypair.js');
require('./index-36930ebb.js');
require('./bip-0039.js');
require('./crypto.js');
require('crypto');
require('./buf.js');
require('./slip-0010.js');

const SLIP44_VEGA_COINTYPE = 1789;
const VEGA_DEFAULT_KEYSPACE = 0;

class VegaWallet extends hdWallet.Wallet {
  static async fromMnemonic (mnemonic) {
    const master = await super.fromMnemonic(mnemonic);
    const vega = await master.child(hdWallet.HARDENED + SLIP44_VEGA_COINTYPE);
    const defaultUsage = await vega.child(hdWallet.HARDENED + VEGA_DEFAULT_KEYSPACE);

    return defaultUsage
  }
}

exports.HARDENED = hdWallet.HARDENED;
exports.PublicKey = keypair.PublicKey;
exports.SLIP44_VEGA_COINTYPE = SLIP44_VEGA_COINTYPE;
exports.VEGA_DEFAULT_KEYSPACE = VEGA_DEFAULT_KEYSPACE;
exports.VegaWallet = VegaWallet;
