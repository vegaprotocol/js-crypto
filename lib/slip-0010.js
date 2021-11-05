import assert from 'nanoassert'
import { hmacSha512 } from './crypto.js'
import * as buf from './buf.js'

/**
 * BIP-0032 Secp256k1 (Bitcoin) key derivation
 * @type {string}
 */
export const CURVE_SECP256K1 = 'Bitcoin seed'

/**
 * SLIP-0010 NIST P-256 key derivation
 * @type {string}
 */
export const CURVE_NIST256P1 = 'Nist256p1 seed'

/**
 * SLIP-0010 Ed25519 key derivation
 * @type {string}
 */
export const CURVE_ED25519 = 'ed25519 seed'

/**
 * Master key derivation
 *
 * @async
 * @param  {Uint8Array} seed
 * @param  {string} curve
 * @return {Promise<{ secretKey: Uint8Array, chainCode: Uint8Array }>}
 */
export async function master (seed, curve) {
  assert(curve === CURVE_ED25519, 'Only Ed25519 is supported for now')
  assert(seed instanceof Uint8Array)

  const key = buf.string(curve)
  const data = seed

  const I = await hmacSha512(key, data)

  return {
    secretKey: I.subarray(0, 32),
    chainCode: I.subarray(32, 64)
  }
}

/**
 * Hardended child node offset
 * @type {number}
 */
export const HARDENED_OFFSET = 0x8000_0000

/**
 * Child key derivation
 *
 * @async
 * @param  {Uint8Array} parentSecretKey
 * @param  {Uint8Array} parentChainCode
 * @param  {number} index
 * @return {Promise<{ secretKey: Uint8Array, chainCode: Uint8Array }>}
 */
export async function child (parentSecretKey, parentChainCode, index) {
  assert(parentSecretKey instanceof Uint8Array)
  assert(parentSecretKey.byteLength === 32)
  assert(parentChainCode instanceof Uint8Array)
  assert(parentChainCode.byteLength === 32)
  assert(index >= 0)
  assert(index >= HARDENED_OFFSET, 'Ed25519 only supports hardened derivation')

  const key = parentChainCode
  const data = buf.concat(buf.u8(0x00), parentSecretKey, buf.u32be(index))
  const I = await hmacSha512(key, data)

  return {
    secretKey: I.subarray(0, 32),
    chainCode: I.subarray(32, 64)
  }
}
