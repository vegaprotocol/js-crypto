'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var index = require('./index-36930ebb.js');
var crypto = require('./crypto.js');
var buf = require('./buf.js');
require('crypto');

/**
 * BIP-0032 Secp256k1 (Bitcoin) key derivation
 * @type {string}
 */
const CURVE_SECP256K1 = 'Bitcoin seed';

/**
 * SLIP-0010 NIST P-256 key derivation
 * @type {string}
 */
const CURVE_NIST256P1 = 'Nist256p1 seed';

/**
 * SLIP-0010 Ed25519 key derivation
 * @type {string}
 */
const CURVE_ED25519 = 'ed25519 seed';

/**
 * Master key derivation
 *
 * @async
 * @param  {Uint8Array} seed
 * @param  {string} curve
 * @return {Promise<{ secretKey: Uint8Array, chainCode: Uint8Array }>}
 */
async function master (seed, curve) {
  index.nanoassert(curve === CURVE_ED25519, 'Only Ed25519 is supported for now');
  index.nanoassert(seed instanceof Uint8Array);

  const key = buf.string(curve);
  const data = seed;

  const I = await crypto.hmacSha512(key, data);

  return {
    secretKey: I.subarray(0, 32),
    chainCode: I.subarray(32, 64)
  }
}

/**
 * Hardended child node offset
 * @type {number}
 */
const HARDENED_OFFSET = 0x8000_0000;

/**
 * Child key derivation
 *
 * @async
 * @param  {Uint8Array} parentSecretKey
 * @param  {Uint8Array} parentChainCode
 * @param  {number} index
 * @return {Promise<{ secretKey: Uint8Array, chainCode: Uint8Array }>}
 */
async function child (parentSecretKey, parentChainCode, index$1) {
  index.nanoassert(parentSecretKey instanceof Uint8Array);
  index.nanoassert(parentSecretKey.byteLength === 32);
  index.nanoassert(parentChainCode instanceof Uint8Array);
  index.nanoassert(parentChainCode.byteLength === 32);
  index.nanoassert(index$1 >= 0);
  index.nanoassert(index$1 >= HARDENED_OFFSET, 'Ed25519 only supports hardened derivation');

  const key = parentChainCode;
  const data = buf.concat(buf.u8(0x00), parentSecretKey, buf.u32be(index$1));
  const I = await crypto.hmacSha512(key, data);

  return {
    secretKey: I.subarray(0, 32),
    chainCode: I.subarray(32, 64)
  }
}

exports.CURVE_ED25519 = CURVE_ED25519;
exports.CURVE_NIST256P1 = CURVE_NIST256P1;
exports.CURVE_SECP256K1 = CURVE_SECP256K1;
exports.HARDENED_OFFSET = HARDENED_OFFSET;
exports.child = child;
exports.master = master;
