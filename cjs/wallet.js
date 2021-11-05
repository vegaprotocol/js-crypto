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

class VegaWallet extends hdWallet.Wallet {
  static async fromMnemonic (mnemonic) {
    const master = await super.fromMnemonic(mnemonic);
    const vega = await master.child(hdWallet.HARDENED + 1789);
    const defaultUsage = await vega.child(hdWallet.HARDENED + 0);

    return defaultUsage
  }
}

exports.HARDENED = hdWallet.HARDENED;
exports.PublicKey = keypair.PublicKey;
exports.VegaWallet = VegaWallet;
