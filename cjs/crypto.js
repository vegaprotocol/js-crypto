'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var index = require('./index-36930ebb.js');
var crypto = require('crypto');

function randomFill (buf) {
  index.nanoassert(buf.byteLength < 2 ** 16, 'A maximum of 2**16-1 bytes can be fulfilled');
  crypto.randomFillSync(buf);

  return buf
}

/**
 * @async
 * @param  {Uint8Array} password
 * @param  {Uint8Array} salt
 * @param  {number} iterations
 * @param  {number} bytes
 * @return {Promise<Uint8Array>}
 */
function pbkdf2Sha512 (password, salt, iterations, bytes) {
  index.nanoassert(password instanceof Uint8Array);
  index.nanoassert(salt instanceof Uint8Array);
  index.nanoassert(iterations > 0 && iterations <= 2 ** 53);
  index.nanoassert(bytes > 0 && bytes <= 64);

  return new Promise((resolve, reject) => {
    crypto.pbkdf2(
      password,
      salt,
      iterations,
      bytes,
      'sha512',
      (err, seed) => {
        if (err) return reject(err)
        resolve(seed);
      }
    );
  })
}

/**
 * This function is async to keep the same API as SubtleCrypto
 * @async
 * @param  {Uint8Array} key
 * @param  {Uint8Array} data
 * @return {Promise<Uint8Array>}
 */
async function hmacSha512 (key, data) {
  index.nanoassert(key instanceof Uint8Array);
  index.nanoassert(data instanceof Uint8Array);

  return crypto.createHmac('sha512', key)
    .update(data)
    .digest()
}

/**
 * @async
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
async function sha256 (data) {
  return Promise.resolve(crypto.createHash('SHA256').update(data).digest())
}

exports.hmacSha512 = hmacSha512;
exports.pbkdf2Sha512 = pbkdf2Sha512;
exports.randomFill = randomFill;
exports.sha256 = sha256;
