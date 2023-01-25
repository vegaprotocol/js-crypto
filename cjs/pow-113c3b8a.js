'use strict';

var sha3r24 = require('./sha3r24.js');

const hash = sha3r24.hash;
const name = sha3r24.name;

/**
 * @param {number} difficulty
 * @param {string} blockHash
 * @param {string} tid
 * @param {bigint} [startNonce=0n]
 */
async function solve (difficulty, blockHash, tid, startNonce = 0n) {
  return {
    nonce: await sha3r24.solve(difficulty, blockHash, tid, startNonce),
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
  const solution = await sha3r24.hash(blockHash, tid, nonce);

  return clzBE(solution) >= difficulty
}

/**
 * @param {Uint8Array} bytes
 */
function clzBE (bytes) {
  let zeros = 0;
  for (const byte of bytes) {
    if (byte === 0) zeros += 8;
    else {
      zeros += Math.clz32(byte) - 24;
      break
    }
  }

  return zeros
}

var pow = /*#__PURE__*/Object.freeze({
  __proto__: null,
  hash: hash,
  name: name,
  solve: solve,
  verify: verify
});

exports.hash = hash;
exports.name = name;
exports.pow = pow;
exports.solve = solve;
exports.verify = verify;
