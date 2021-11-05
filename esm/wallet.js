import { Wallet, HARDENED } from './hd-wallet.js';
export { HARDENED } from './hd-wallet.js';
export { PublicKey } from './keypair.js';
import './index-a447e129.js';
import './bip-0039.js';
import './crypto.js';
import 'crypto';
import './buf.js';
import './slip-0010.js';

class VegaWallet extends Wallet {
  static async fromMnemonic (mnemonic) {
    const master = await super.fromMnemonic(mnemonic);
    const vega = await master.child(HARDENED + 1789);
    const defaultUsage = await vega.child(HARDENED + 0);

    return defaultUsage
  }
}

export { VegaWallet };
