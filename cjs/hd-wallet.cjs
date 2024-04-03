'use strict';

var assert = require('nanoassert');
var seed = require('./bip-0039/seed.cjs');
var slip0010 = require('./slip-0010.cjs');
var keypair = require('./keypair.cjs');
var buf = require('./buf.cjs');
var crate = require('./crate.cjs');

// Private accessors
const kChainCode = Symbol('ChainCode');
const kSecretKey = Symbol('SecretKey');

/**
 * SLIP-0010 Ed25519 key derivation
 * @type {string}
 */
const CURVE_ED25519 = slip0010.CURVE_ED25519;

/**
 * Hardended child node offset. Use with `.child(index + HARDENED)` or
 * `.keyPair(index + HARDENED)`
 * @type {number}
 */
const HARDENED = slip0010.HARDENED_OFFSET;

class HDWallet {
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
   * This is a non-standard method to get the public key for an internal HD node
   * This is used in Vega to identify a wallet
   *
   * @returns {Promise<string>}
   */
  async generatePublicKey () {
    return buf.toHex((await crate.wasm).ed25519_keypair_from_seed(this[kSecretKey]).subarray(32))
  }

  /**
   * Derive a child node from the current wallet. Index ≥ 2^31 creates a
   * hardened child node.
   * @async
   * @param  {number} index
   * @return {Promise<{ secretKey, chainCode }>}
   */
  _deriveChild (index) {
    return slip0010.child(this[kSecretKey], this[kChainCode], index)
  }

  /**
   * Derive a new sub-wallet from the current wallet. Index ≥ 2^31 creates a
   * hardened child node.
   * @async
   * @param  {number} index
   * @return {Promise<HDWallet>}
   */
  async child (index) {
    const { secretKey, chainCode } = await this._deriveChild(index);

    return new this.constructor(secretKey, chainCode)
  }

  /**
   * @async
   * @param  {number} index
   * @return {Promise<KeyPair>}
   */
  async keyPair (index) {
    const { secretKey } = await this._deriveChild(index);

    return await keypair.KeyPair.fromSeed(index, secretKey)
  }

  /**
   * Create a new BIP-0039 derived wallet. Note that the mnemonic is not
   * validated.
   *
   * @async
   * @param  {string | Uint8Array} mnemonic - BIP-0039 space delimited mnemonic
   * @param  {string | Uint8Array} [password=""] - Optional password
   * @param  {string} [curve=CURVE_ED25519] - Elliptic Curve
   * @return {Promise<HDWallet>}
   */
  static async fromMnemonic (mnemonic, password, curve = CURVE_ED25519) {
    assert(curve === CURVE_ED25519, 'Only Ed25519 is supported for now');

    const seed = await this.deriveSeed(mnemonic, password);

    return this.fromSeed(seed, curve)
  }

  /**
   * Helper to derive a BIP-0039 seed from a mnemonic. Not that the mnemonic is
   * not validated.
   *
   * @async
   * @param  {string | Uint8Array} mnemonic - BIP-0039 space delimited mnemonic
   * @param  {string | Uint8Array} [password=""] - Optional password
   * @returns {Promise<Uint8Array>}
   */
  static async deriveSeed (mnemonic, password = '') {
    assert(mnemonic instanceof Uint8Array || typeof mnemonic === 'string');
    assert(password instanceof Uint8Array || typeof password === 'string');

    return seed.seed(mnemonic, password)
  }

  /**
   * Create a new wallet from a seed.
   *
   * @async
   * @param  {Uint8Array} seed
   * @param  {string} [curve=CURVE_ED25519] - Elliptic Curve
   * @return {Promise<HDWallet>}
   */
  static async fromSeed (seed, curve = CURVE_ED25519) {
    assert(seed instanceof Uint8Array);
    assert(curve === CURVE_ED25519, 'Only Ed25519 is supported for now');

    const { secretKey, chainCode } = await slip0010.master(seed, curve);

    return new this(secretKey, chainCode)
  }
}

exports.CURVE_ED25519 = CURVE_ED25519;
exports.HARDENED = HARDENED;
exports.HDWallet = HDWallet;
