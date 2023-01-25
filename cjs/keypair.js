'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var index = require('./index-36930ebb.js');
var crate = require('./crate.js');
var buf = require('./buf.js');

class PublicKey {
  /**
   * @param {Uint8Array} pk - 32-byte secret key
   */
  constructor (pk) {
    index.nanoassert(pk instanceof Uint8Array);
    index.nanoassert(pk.byteLength === 32);

    /** @private */
    this._pk = pk;
  }

  /**
   * Verify Vega EdDSA signature on message. Vega EdDSA is a EdDSA signature
   * over the SHA3-256 digest of message
   * @param  {Uint8Array} signature
   * @param  {Uint8Array} message
   * @return {Promise<boolean>}
   */
  async verify (signature, message) {
    index.nanoassert(signature instanceof Uint8Array);
    index.nanoassert(signature.byteLength === 64);
    index.nanoassert(message instanceof Uint8Array);
    const digest = (await crate.wasm).sha3_256_hash(message);
    return (await crate.wasm).ed25519_verify(signature, digest, this._pk)
  }

  /**
   * Encode public key as hex string
   * @return {string}
   */
  toString () {
    return buf.toHex(this._pk)
  }

  toJSON () {
    return this.toString()
  }
}

/** @type {number} Byte length of a public key */
PublicKey.BYTES = 32;

class SecretKey {
  /**
   * @param {Uint8Array} sk - 64-byte secret key
   */
  constructor (sk) {
    index.nanoassert(sk instanceof Uint8Array);
    index.nanoassert(sk.byteLength === 64);

    /** @private */
    this._sk = sk;
  }

  /**
   * Create a Vega EdDSA signature on message. Vega EdDSA is a EdDSA signature
   * over the SHA3-256 digest of message
   * @param  {Uint8Array} message
   * @return {Promise<Uint8Array>}
   */
  async sign (message) {
    index.nanoassert(message instanceof Uint8Array);
    const digest = (await crate.wasm).sha3_256_hash(message);
    return (await crate.wasm).ed25519_sign(digest, this._sk)
  }

  /**
   * Encode secret key as hex string
   * @return {string}
   */
  toString () {
    return buf.toHex(this._sk)
  }

  toJSON () {
    return this.toString()
  }
}

/** @type {number} Byte length of a secret key */
SecretKey.BYTES = 64;

class KeyPair {
  constructor (index, secretKey, publicKey) {
    this.index = index;
    /** @private */
    this.pk = new PublicKey(publicKey);

    /** @private */
    this.sk = new SecretKey(secretKey);
  }

  /**
   * Verify Vega EdDSA signature on message. Vega EdDSA is a EdDSA signature
   * over the SHA3-256 digest of message
   * @async
   * @param  {Uint8Array} signature
   * @param  {Uint8Array} message
   * @return {Promise<boolean>}
   */
  verify (signature, message) {
    return this.pk.verify(signature, message)
  }

  /**
   * Create a Vega EdDSA signature on message. Vega EdDSA is a EdDSA signature
   * over the SHA3-256 digest of message
   * @async
   * @param  {Uint8Array} message
   * @return {Promise<Uint8Array>}
   */
  sign (message) {
    return this.sk.sign(message)
  }

  static async fromSeed (index, seed) {
    const sk = (await crate.wasm).ed25519_keypair_from_seed(seed);

    return new this(index, sk, sk.subarray(32))
  }
}

exports.KeyPair = KeyPair;
exports.PublicKey = PublicKey;
exports.SecretKey = SecretKey;
