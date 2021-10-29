import crate from '../crate/Cargo.toml'
import { hex } from './buf.mjs'

const wasm = crate()

export class PublicKey {
  constructor (pk) {
    this._pk = pk
  }

  async verify (signature, message) {
    return (await wasm).verify(signature, message, this._pk)
  }

  toString () {
    return hex(this._pk)
  }
}

class SecretKey {
  constructor (sk) {
    this._sk = sk
  }

  async sign (message) {
    return (await wasm).sign(message, this._sk)
  }

  toString () {
    return hex(this._sk)
  }
}

export class KeyPair {
  constructor (index, secretKey, publicKey) {
    this.index = index
    this.pk = new PublicKey(publicKey)
    this.sk = new SecretKey(secretKey)
    this.tainted = false
  }

  async verify (signature, message) {
    return this.pk.sign(signature, message)
  }

  async sign (message) {
    return this.sk.sign(message)
  }

  static async fromSeed (index, seed) {
    const sk = (await wasm).keypair_from_seed(seed)

    return new this(index, sk, sk.subarray(32))
  }

  toJSON () {
    return {
      index: this.index,
      public_key: this.pk.toString(),
      private_key: this.sk.toString(),
      meta: [],
      tainted: this.tainted,
      algorithm: {
        name: 'vega/ed25519',
        version: 1
      }
    }
  }
}
