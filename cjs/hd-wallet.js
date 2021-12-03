'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var index = require('./index-36930ebb.js');
var bip0039 = require('./bip-0039.js');
var slip0010 = require('./slip-0010.js');
var keypair = require('./keypair.js');
require('./crypto.js');
require('crypto');
require('./buf.js');

// Private accessors
const kChainCode = Symbol('ChainCode');
const kSecretKey = Symbol('SecretKey');

/**
 * SLIP-0010 Ed25519 key derivation
 * @type {string}
 */
const CURVE_ED25519 = slip0010.CURVE_ED25519;

/**
 * Hardened child node offset. Use with `.child(index + HARDENED)` or
 * `.keyPair(index + HARDENED)`
 * @type {number}
 */
const HARDENED = slip0010.HARDENED_OFFSET;

class Wallet {
  /**
   * Create a new subnode (wallet) from a secret key and chain code. Use the
   * static functions `fromSeed` and `fromMnemonic` to create a new master
   * wallet
   *
   * @param  {Uint8Array} secretKey - 32 bytes secret key
   * @param  {Uint8Array} chainCode - 32 bytes chain code
   */
  constructor (secretKey, chainCode) {
    /** @private */
    this[kChainCode] = chainCode;
    /** @private */
    this[kSecretKey] = secretKey;
  }

  /**
   * Derive a new sub-wallet from the current wallet. Index ≥ 2^31 creates a
   * hardended child node.
   * @async
   * @param  {number} index
   * @return {Promise<Wallet>}
   */
  async child (index) {
    const { secretKey, chainCode } = await slip0010.child(this[kSecretKey], this[kChainCode], index);

    return new Wallet(secretKey, chainCode)
  }

  /**
   * @async
   * @param  {number} index
   * @return {Promise<KeyPair>}
   */
  async keyPair (index) {
    const { secretKey } = await slip0010.child(this[kSecretKey], this[kChainCode], index);

    return await keypair.KeyPair.fromSeed(secretKey)
  }

  /**
   * Create a new BIP-0039 derived wallet. Note that the mnemonic is not
   * validated.
   *
   * @async
   * @param  {string | Uint8Array} mnemonic - BIP-0039 space delimited mnemonic
   * @param  {string | Uint8Array} [password=""] - Optional password
   * @param  {string} [curve=CURVE_ED25519] - Elliptic Curve
   * @return {Promise<Wallet>}
   */
  static async fromMnemonic (mnemonic, password = '', curve = CURVE_ED25519) {
    index.nanoassert(mnemonic instanceof Uint8Array || typeof mnemonic === 'string');
    index.nanoassert(password instanceof Uint8Array || typeof password === 'string');
    index.nanoassert(curve === CURVE_ED25519, 'Only Ed25519 is supported for now');

    const seed = await bip0039.seed(mnemonic, password);

    return this.fromSeed(seed, curve)
  }

  /**
   * Create a new wallet from a seed.
   *
   * @async
   * @param  {Uint8Array} seed
   * @param  {string} [curve=CURVE_ED25519] - Elliptic Curve
   * @return {Promise<Wallet>}
   */
  static async fromSeed (seed, curve = CURVE_ED25519) {
    index.nanoassert(seed instanceof Uint8Array);
    index.nanoassert(curve === CURVE_ED25519, 'Only Ed25519 is supported for now');

    const { secretKey, chainCode } = await slip0010.master(seed, curve);

    return new Wallet(secretKey, chainCode)
  }
}

exports.CURVE_ED25519 = CURVE_ED25519;
exports.HARDENED = HARDENED;
exports.Wallet = Wallet;
