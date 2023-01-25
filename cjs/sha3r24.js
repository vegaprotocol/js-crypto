'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var crate = require('./crate.js');
var buf = require('./buf.js');
var index = require('./index-36930ebb.js');

const name = 'sha3_24_rounds';

/**
 * @param {number} difficulty
 * @param {string} blockHash
 * @param {string} tid
 * @param {bigint} [startNonce=0n]
 */
async function solve (difficulty, blockHash, tid, startNonce = 0n) {
  const crate$1 = await crate.wasm;

  index.nanoassert(difficulty <= 50 && difficulty > 0);
  index.nanoassert(typeof blockHash === 'string', 'blockHash must be hex string');
  index.nanoassert(blockHash.length === 64, 'blockHash must be 64 hex chars');
  index.nanoassert(typeof tid === 'string', 'tid must be hex string');
  index.nanoassert(tid.length === 64, 'tid must be 64 hex chars');
  index.nanoassert(typeof startNonce === 'bigint', 'startNonce must be bigint');
  index.nanoassert(startNonce >= 0, 'startNonce must be positive');

  return crate$1.sha3r24_pow_solve(difficulty, buf.string(blockHash), buf.string(tid), startNonce)
}

async function hash (blockHash, tid, nonce) {
  const crate$1 = await crate.wasm;

  index.nanoassert(typeof blockHash === 'string', 'blockHash must be hex string');
  index.nanoassert(blockHash.length === 64, 'blockHash must be 64 hex chars');
  index.nanoassert(typeof tid === 'string', 'tid must be hex string');
  index.nanoassert(tid.length === 64, 'tid must be 64 hex chars');

  return crate$1.sha3r24_pow_hash(buf.string(blockHash), buf.string(tid), nonce)
}

exports.hash = hash;
exports.name = name;
exports.solve = solve;
