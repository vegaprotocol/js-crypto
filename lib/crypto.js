import assert from 'nanoassert'
import { createHash, createHmac, pbkdf2, randomFillSync as _randomFill } from 'crypto'

export function randomFill (buf) {
  assert(buf.byteLength < 2 ** 16, 'A maximum of 2**16-1 bytes can be fulfilled')
  _randomFill(buf)

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
export function pbkdf2Sha512 (password, salt, iterations, bytes) {
  assert(password instanceof Uint8Array)
  assert(salt instanceof Uint8Array)
  assert(iterations > 0 && iterations <= 2 ** 53)
  assert(bytes > 0 && bytes <= 64)

  return new Promise((resolve, reject) => {
    pbkdf2(
      password,
      salt,
      iterations,
      bytes,
      'sha512',
      (err, seed) => {
        if (err) return reject(err)
        resolve(seed)
      }
    )
  })
}

/**
 * This function is async to keep the same API as SubtleCrypto
 * @async
 * @param  {Uint8Array} key
 * @param  {Uint8Array} data
 * @return {Promise<Uint8Array>}
 */
export async function hmacSha512 (key, data) {
  assert(key instanceof Uint8Array)
  assert(data instanceof Uint8Array)

  return createHmac('sha512', key)
    .update(data)
    .digest()
}

/**
 * @async
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
export async function sha256 (data) {
  return Promise.resolve(createHash('SHA256').update(data).digest())
}
