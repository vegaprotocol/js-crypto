import { n as nanoassert } from './index-a447e129.js';
import { pbkdf2, createHmac } from 'crypto';

/**
 * @async
 * @param  {Uint8Array} password
 * @param  {Uint8Array} salt
 * @param  {number} iterations
 * @param  {number} bytes
 * @return {Promise<Uint8Array>}
 */
function pbkdf2Sha512 (password, salt, iterations, bytes) {
  nanoassert(password instanceof Uint8Array);
  nanoassert(salt instanceof Uint8Array);
  nanoassert(iterations > 0 && iterations <= 2 ** 53);
  nanoassert(bytes > 0 && bytes <= 64);

  return new Promise((resolve, reject) => {
    pbkdf2(
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
  nanoassert(key instanceof Uint8Array);
  nanoassert(data instanceof Uint8Array);

  return createHmac('sha512', key)
    .update(data)
    .digest()
}

export { hmacSha512, pbkdf2Sha512 };
