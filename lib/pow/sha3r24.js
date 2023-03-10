import { wasm } from '../crate.js'
import { string } from '../buf.js'
import assert from 'nanoassert'

export const name = 'sha3_24_rounds'

const U64_MAX = 2n ** 64n - 1n

/**
 * @param {number} difficulty
 * @param {string} blockHash
 * @param {string} tid
 * @param {bigint} [startNonce=0n]
 */
export async function solve (difficulty, blockHash, tid, startNonce = 0n, endNonce = U64_MAX) {
  const crate = await wasm

  assert(difficulty <= 50 && difficulty > 0)
  assert(typeof blockHash === 'string', 'blockHash must be hex string')
  assert(blockHash.length === 64, 'blockHash must be 64 hex chars')
  assert(typeof tid === 'string', 'tid must be hex string')
  assert(tid.length === 64, 'tid must be 64 hex chars')
  assert(typeof startNonce === 'bigint', 'startNonce must be bigint')
  assert(startNonce >= 0, 'startNonce must be positive')
  assert(startNonce <= U64_MAX, 'startNonce must be U64')

  return crate.sha3r24_pow_solve(difficulty, string(blockHash), string(tid), startNonce, endNonce)
}

export async function hash (blockHash, tid, nonce) {
  const crate = await wasm

  assert(typeof blockHash === 'string', 'blockHash must be hex string')
  assert(blockHash.length === 64, 'blockHash must be 64 hex chars')
  assert(typeof tid === 'string', 'tid must be hex string')
  assert(tid.length === 64, 'tid must be 64 hex chars')

  return crate.sha3r24_pow_hash(string(blockHash), string(tid), nonce)
}
