'use strict'

const assert = require('nanoassert')
const crypto = require('./crypto.cjs')
const buf = require('./buf.cjs')

/**
 * SLIP-0010 Ed25519 key derivation
 * @type {string}
 */
const CURVE_ED25519 = 'ed25519 seed'

/**
 * Hardended child node offset
 * @type {number}
 */
const HARDENED_OFFSET = 0x8000_0000

/**
 * Master key derivation
 *
 * @async
 * @param  {Uint8Array} seed
 * @param  {string} curve
 * @return {Promise<{ secretKey: Uint8Array, chainCode: Uint8Array }>}
 */
async function master (seed, curve) {
  assert(curve === CURVE_ED25519, 'Only Ed25519 is supported for now')
  assert(seed instanceof Uint8Array || typeof seed === 'string')

  const key = buf.string(curve)
  const data = buf.string(seed)

  const I = await crypto.hmacSha512(key, data)

  return {
    secretKey: I.subarray(0, 32),
    chainCode: I.subarray(32, 64)
  }
}

/**
 * Child key derivation
 *
 * @async
 * @param  {Uint8Array} parentSecretKey
 * @param  {Uint8Array} parentChainCode
 * @param  {number} index
 * @return {Promise<{ secretKey: Uint8Array, chainCode: Uint8Array }>}
 */
async function child (parentSecretKey, parentChainCode, index) {
  assert(parentSecretKey instanceof Uint8Array)
  assert(parentSecretKey.byteLength === 32)
  assert(parentChainCode instanceof Uint8Array)
  assert(parentChainCode.byteLength === 32)
  assert(index >= 0)
  assert(index >= HARDENED_OFFSET, 'Ed25519 only supports hardened derivation')
  assert(index < 2 ** 32)

  const key = parentChainCode
  const data = buf.concat(buf.u8(0x00), parentSecretKey, buf.u32be(index))
  const I = await crypto.hmacSha512(key, data)

  return {
    secretKey: I.subarray(0, 32),
    chainCode: I.subarray(32, 64)
  }
}

exports.CURVE_ED25519 = CURVE_ED25519
exports.HARDENED_OFFSET = HARDENED_OFFSET
exports.child = child
exports.master = master
