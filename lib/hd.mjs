import assert from 'nanoassert'
import * as crypto from './crypto.js'
import * as buf from './buf.js'

const BIP39_SALT_PREFIX = buf.string('mnemonic')
const BIP39_ITERATIONS = 2048
const BIP39_KEYBYTES = 64

/**
 * @param {string | Uint8Array} mnemonic
 * @param {string | Uint8Array} walletPassword
 */
async function bip39Seed (mnemonic, walletPassword = '') {
  assert(mnemonic instanceof Uint8Array || typeof mnemonic === 'string')
  assert(walletPassword instanceof Uint8Array || typeof walletPassword === 'string')

  const salt = buf.concat(BIP39_SALT_PREFIX, buf.string(walletPassword))
  const password = buf.string(mnemonic)

  return crypto.pbkdf2Sha512(
    password,
    salt,
    BIP39_ITERATIONS,
    BIP39_KEYBYTES
  )
}

const SLIP10_ED25519_SEED = buf.string('ed25519 seed')
const SLIP44_VEGA_COINTYPE = 1789
const SLIP10_HARDENED = 0x8000_0000

/**
 * @param {string | Uint8Array} seed
 */
async function masterNode (seed) {
  const key = SLIP10_ED25519_SEED
  const data = buf.string(seed)
  const I = await crypto.hmacSha512(key, data)

  return {
    masterKey: I.subarray(0, 32),
    masterChainCode: I.subarray(32, 64)
  }
}

/**
 * @param {Uint8Array} parentChainCode
 * @param {string | Uint8Array} parentKey
 * @param {number} index
 */
async function hardenedChildNode (parentChainCode, parentKey, index) {
  const key = parentChainCode
  const data = buf.concat(buf.u8(0x00), buf.string(parentKey), buf.u32be((SLIP10_HARDENED | index) >>> 0))
  const I = await crypto.hmacSha512(key, data)

  return {
    childKey: I.subarray(0, 32),
    childChainCode: I.subarray(32, 64)
  }
}

/**
 * @param {string | Uint8Array} mnemonic
 */
async function wallet (mnemonic) {
  const seed = await bip39Seed(mnemonic)

  const { masterKey, masterChainCode } = await masterNode(seed)

  const {
    childChainCode: vegaChainCode,
    childKey: vegaKey
  } = await hardenedChildNode(masterChainCode, masterKey, SLIP44_VEGA_COINTYPE)

  const {
    childChainCode,
    childKey
  } = await hardenedChildNode(vegaChainCode, vegaKey, 0)

  return async function derive (/** @type {number} */ index) {
    const {
      childKey: privateKey
    } = await hardenedChildNode(childChainCode, childKey, index)

    return privateKey
  }
}

export {
  SLIP44_VEGA_COINTYPE as VEGA_COINTYPE,
  bip39Seed,
  masterNode,
  hardenedChildNode,
  wallet as default
}
