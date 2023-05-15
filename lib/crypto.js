import assert from 'nanoassert'
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  pbkdf2,
  randomFillSync as _randomFill
} from 'crypto'

export function randomFill (buf) {
  assert(
    buf.byteLength < 2 ** 16,
    'A maximum of 2**16-1 bytes can be fulfilled'
  )
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
    pbkdf2(password, salt, iterations, bytes, 'sha512', (err, seed) => {
      if (err) return reject(err)
      resolve(seed)
    })
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

  return createHmac('sha512', key).update(data).digest()
}

/**
 * @async
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
export async function sha256 (data) {
  return Promise.resolve(createHash('SHA256').update(data).digest())
}

/**
 * @async
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array} data
 * @param {Uint8Array} aad
 * @returns {Promise<Uint8Array>}
 */
export async function aes256gcmEncrypt (key, nonce, data, aad) {
  assert(data instanceof Uint8Array)
  assert(key instanceof Uint8Array)
  assert(nonce instanceof Uint8Array)
  assert(aad instanceof Uint8Array)

  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(aad)
  return Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()])
}

/**
 * @async
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array} data
 * @param {Uint8Array} aad
 * @returns {Promise<Uint8Array>}
 */
export async function aes256gcmDecrypt (key, nonce, data, aad) {
  assert(data instanceof Uint8Array)
  assert(key instanceof Uint8Array)
  assert(nonce instanceof Uint8Array)
  assert(aad instanceof Uint8Array)

  const cipher = createDecipheriv('aes-256-gcm', key, nonce)
  const tag = data.subarray(-16)
  cipher.setAuthTag(tag)
  cipher.setAAD(aad)
  const plaintext = cipher.update(data.subarray(0, -16))
  cipher.final()

  return plaintext
}
