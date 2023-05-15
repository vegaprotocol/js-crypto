'use strict'

const assert = require('nanoassert')
const crate = require('./crate.cjs')
const buf = require('./buf.cjs')

const VEGA_ALGORITHM_NAME = 'vega/ed25519'
const VEGA_ALGORITHM_VERSION = 1

const CHAIN_ID_DELIMITER = buf.string('\0')

async function _hash (message, chainId) {
  if (chainId != null) message = buf.concat(buf.string(chainId), CHAIN_ID_DELIMITER, message)
  const digest = (await crate.wasm).sha3_256_hash(message)

  return digest
}

class PublicKey {
  /**
   * @param {Uint8Array} pk - 32-byte secret key
   */
  constructor (pk) {
    assert(pk instanceof Uint8Array)
    assert(pk.byteLength === 32)

    /** @private */
    this._pk = pk
  }

  /**
   * Verify Vega EdDSA signature on message. Vega EdDSA is a EdDSA signature
   * over the SHA3-256 digest of message
   * @param  {Uint8Array} signature
   * @param  {Uint8Array} message
   * @param  {string | Uint8Array} [chainId]
   * @return {Promise<boolean>}
   */
  async verify (signature, message, chainId) {
    assert(signature instanceof Uint8Array)
    assert(signature.byteLength === 64)
    assert(message instanceof Uint8Array)

    const digest = await this.hash(message, chainId)
    return this.verifyRaw(signature, digest)
  }

  /**
   * Verify a direct EdDSA signature
   *
   * @param {Uint8Array} bytes
   * @returns
   */
  async verifyRaw (signature, bytes) {
    return (await crate.wasm).ed25519_verify(signature, bytes, this._pk)
  }

  /**
   * Compute the SHA3-256 digest of message, optionally prepending chainId and the delimiter
   * @param {Uint8Array} message
   * @param {string|Uint8Array} [chainId]
   * @returns
   */
  async hash (message, chainId) {
    return _hash(message, chainId)
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
PublicKey.BYTES = 32

class SecretKey {
  /**
   * @param {Uint8Array} sk - 64-byte secret key
   */
  constructor (sk) {
    assert(sk instanceof Uint8Array)
    assert(sk.byteLength === 64)

    /** @private */
    this._sk = sk
  }

  /**
   * Create a Vega EdDSA signature on message. Vega EdDSA is a EdDSA signature
   * over the SHA3-256 digest of message, optionally prepending chainId and the delimiter
   * @param  {Uint8Array} message
   * @param  {string | Uint8Array} [chainId]
   * @return {Promise<Uint8Array>}
   */
  async sign (message, chainId) {
    assert(message instanceof Uint8Array)

    const digest = await this.hash(message, chainId)

    return this.signRaw(digest)
  }

  /**
   * Create a direct EdDSA signature
   *
   * @param {Uint8Array} bytes
   * @returns
   */
  async signRaw (bytes) {
    return (await crate.wasm).ed25519_sign(bytes, this._sk)
  }

  /**
   * Compute the SHA3-256 digest of message, optionally prepending chainId and the delimiter
   * @param {Uint8Array} message
   * @param {string|Uint8Array} [chainId]
   * @returns
   */
  async hash (message, chainId) {
    return _hash(message, chainId)
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
SecretKey.BYTES = 64

class KeyPair {
  constructor (index, secretKey, publicKey) {
    this.algorithm = {
      name: VEGA_ALGORITHM_NAME,
      version: VEGA_ALGORITHM_VERSION
    }

    this.index = index

    this.publicKey = new PublicKey(publicKey)

    /** @private */
    this.secretKey = new SecretKey(secretKey)
  }

  /**
   * Verify Vega EdDSA signature on message. Vega EdDSA is a EdDSA signature
   * over the SHA3-256 digest of message
   * @async
   * @param  {Uint8Array} signature
   * @param  {Uint8Array} message
   * @param  {string | Uint8Array} [chainId]
   * @return {Promise<boolean>}
   */
  verify (signature, message, chainId) {
    return this.publicKey.verify(signature, message, chainId)
  }

  verifyRaw (signature, message) {
    return this.publicKey.verifyRaw(signature, message)
  }

  /**
   * Create a Vega EdDSA signature on message. Vega EdDSA is a EdDSA signature
   * over the SHA3-256 digest of message
   * @async
   * @param  {Uint8Array} message
   * @param  {string | Uint8Array} [chainId]
   * @return {Promise<Uint8Array>}
   */
  sign (message, chainId) {
    return this.secretKey.sign(message, chainId)
  }

  signRaw (message) {
    return this.secretKey.signRaw(message)
  }

  /**
   * Compute the SHA3-256 digest of message, optionally prepending chainId and the delimiter
   * @param {Uint8Array} message
   * @param {string|Uint8Array} [chainId]
   * @returns
   */
  hash (message, chainId) {
    return _hash(message, chainId)
  }

  static async fromSeed (index, seed) {
    const sk = (await crate.wasm).ed25519_keypair_from_seed(seed)

    return new this(index, sk, sk.subarray(32))
  }

  toJSON () {
    return {
      index: this.index,
      publicKey: this.publicKey.toJSON()
    }
  }
}

exports.KeyPair = KeyPair
exports.PublicKey = PublicKey
exports.SecretKey = SecretKey
exports.VEGA_ALGORITHM_NAME = VEGA_ALGORITHM_NAME
exports.VEGA_ALGORITHM_VERSION = VEGA_ALGORITHM_VERSION
