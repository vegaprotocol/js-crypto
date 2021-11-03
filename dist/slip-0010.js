import { n as nanoassert } from './index-a447e129.js';
import { hmacSha512 } from './crypto.js';
import { s as string, c as concat, u as u32be, a as u8 } from './buf-ba61d454.js';
import 'crypto';

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
 * @param  {Uint8Array} seed
 * @param  {string} curve
 * @return {Promise<{ secretKey: Uint8Array, chainCode: Uint8Array }>}
 */
async function master (seed, curve) {
  nanoassert(curve === CURVE_ED25519, 'Only Ed25519 is supported for now');
  nanoassert(seed instanceof Uint8Array);
  nanoassert(seed.byteLength === 64);

  const key = string(curve);
  const data = seed;

  const I = await hmacSha512(key, data);

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
 * @param  {Uint8Array} parentSecretKey
 * @param  {Uint8Array} parentChainCode
 * @param  {number} index
 * @return {Promise<{ secretKey: Uint8Array, chainCode: Uint8Array }>}
 */
async function child (parentSecretKey, parentChainCode, index) {
  nanoassert(parentSecretKey instanceof Uint8Array);
  nanoassert(parentSecretKey.byteLength === 32);
  nanoassert(parentChainCode instanceof Uint8Array);
  nanoassert(parentChainCode.byteLength === 32);
  nanoassert(index >= 0);
  nanoassert(index >= HARDENED_OFFSET, 'Ed25519 only supports hardened derivation');

  const key = parentChainCode;
  const data = concat(u8(0x00), parentSecretKey, u32be(index));
  const I = await hmacSha512(key, data);

  return {
    secretKey: I.subarray(0, 32),
    chainCode: I.subarray(32, 64)
  }
}

export { CURVE_ED25519, CURVE_NIST256P1, CURVE_SECP256K1, HARDENED_OFFSET, child, master };
