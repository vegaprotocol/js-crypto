'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var index = require('./index-36930ebb.js');

const scrypto = window.crypto.subtle;

/**
 * @async
 * @param  {Uint8Array} password
 * @param  {Uint8Array} salt
 * @param  {number} iterations
 * @param  {number} bytes
 * @return {Promise<Uint8Array>}
 */
async function pbkdf2Sha512 (password, salt, iterations, bytes) {
  index.nanoassert(password instanceof Uint8Array);
  index.nanoassert(salt instanceof Uint8Array);
  index.nanoassert(iterations > 0 && iterations <= 2 ** 53);
  index.nanoassert(bytes > 0 && bytes <= 64);

  const _password = await scrypto.importKey(
    'raw',
    password,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const key = await scrypto.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations,
      hash: 'SHA-512'
    },
    _password,
    { name: 'HMAC', hash: 'SHA-512', length: bytes * 8 },
    true,
    []
  );

  return new Uint8Array(await scrypto.exportKey('raw', key))
}

/**
 * @async
 * @param  {Uint8Array} key
 * @param  {Uint8Array} data
 * @return {Promise<Uint8Array>}
 */
async function hmacSha512 (key, data) {
  index.nanoassert(key instanceof Uint8Array);
  index.nanoassert(data instanceof Uint8Array);

  const _key = await scrypto.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-512' },
    false,
    ['sign']
  );

  return new Uint8Array(await scrypto.sign({ name: 'HMAC', hash: 'SHA-512' }, _key, data))
}

exports.hmacSha512 = hmacSha512;
exports.pbkdf2Sha512 = pbkdf2Sha512;
