'use strict'

const sha3r24 = require('./pow/sha3r24.cjs')

const hash = sha3r24.hash
const name = sha3r24.name

/**
 * @param {number} difficulty
 * @param {string} blockHash
 * @param {string} tid
 * @param {bigint} [startNonce=0n]
 * @param {bigint} [endNonce=U64_MAX]
 */
async function solve (difficulty, blockHash, tid, startNonce = undefined, endNonce = undefined) {
  return {
    nonce: await sha3r24.solve(difficulty, blockHash, tid, startNonce, endNonce),
    tid,
    hashFunction: sha3r24.name
  }
}

/**
 * @param {number} difficulty
 * @param {string} blockHash
 * @param {string} tid
 * @param {bigint} nonce
 */
async function verify (difficulty, blockHash, tid, nonce) {
  const solution = await sha3r24.hash(blockHash, tid, nonce)

  return clzBE(solution) >= difficulty
}

/**
 * @param {Uint8Array} bytes
 */
function clzBE (bytes) {
  let zeros = 0
  for (const byte of bytes) {
    if (byte === 0) zeros += 8
    else {
      zeros += Math.clz32(byte) - 24
      break
    }
  }

  return zeros
}

exports.hash = hash
exports.name = name
exports.solve = solve
exports.verify = verify
