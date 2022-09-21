import assert from 'nanoassert'
import { wasm } from './crate.js'
import { hex } from './buf.js'

export class PublicKey {
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
   * @return {Promise<boolean>}
   */
  async verify (signature, message) {
    assert(signature instanceof Uint8Array)
    assert(signature.byteLength === 64)
    assert(message instanceof Uint8Array)
    const digest = (await wasm).sha3_256_hash(message)
    return (await wasm).ed25519_verify(signature, digest, this._pk)
  }

  /**
   * Encode public key as hex string
   * @return {string}
   */
  toString () {
    return hex(this._pk)
  }

  toJSON () {
    return this.toString()
  }
}

/** @type {number} Byte length of a public key */
PublicKey.BYTES = 32

export class SecretKey {
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
   * over the SHA3-256 digest of message
   * @param  {Uint8Array} message
   * @return {Promise<Uint8Array>}
   */
  async sign (message) {
    assert(message instanceof Uint8Array)
    const digest = (await wasm).sha3_256_hash(message)
    return (await wasm).ed25519_sign(digest, this._sk)
  }

  /**
   * Encode secret key as hex string
   * @return {string}
   */
  toString () {
    return hex(this._sk)
  }

  toJSON () {
    return this.toString()
  }
}

/** @type {number} Byte length of a secret key */
SecretKey.BYTES = 64

export class KeyPair {
  constructor (secretKey, publicKey) {
    /** @private */
    this.pk = new PublicKey(publicKey)

    /** @private */
    this.sk = new SecretKey(secretKey)
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

  static async fromSeed (seed) {
    const sk = (await wasm).ed25519_keypair_from_seed(seed)

    return new this(sk, sk.subarray(32))
  }
}
