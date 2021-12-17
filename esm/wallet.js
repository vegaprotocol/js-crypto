import { Wallet, HARDENED } from './hd-wallet.js';
export { HARDENED } from './hd-wallet.js';
export { PublicKey } from './keypair.js';
import './index-a447e129.js';
import './bip-0039.js';
import './crypto.js';
import 'crypto';
import './buf.js';
import './slip-0010.js';

const SLIP44_VEGA_COINTYPE = 1789;
const VEGA_DEFAULT_KEYSPACE = 0;

class VegaWallet extends Wallet {
  static async fromMnemonic (mnemonic) {
    const master = await super.fromMnemonic(mnemonic);
    const vega = await master.child(HARDENED + SLIP44_VEGA_COINTYPE);
    const defaultUsage = await vega.child(HARDENED + VEGA_DEFAULT_KEYSPACE);

    return defaultUsage
  }
}

export { SLIP44_VEGA_COINTYPE, VEGA_DEFAULT_KEYSPACE, VegaWallet };
