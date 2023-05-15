'use strict'

const assert = require('nanoassert')

const crypto = globalThis.crypto
const subtle = crypto.subtle

/**
 * @param {Uint8Array} buf
 */
function randomFill (buf) {
  assert(
    buf.byteLength < 2 ** 16,
    'A maximum of 2**16-1 bytes can be fulfilled'
  )
  crypto.getRandomValues(buf)

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
async function pbkdf2Sha512 (password, salt, iterations, bytes) {
  assert(password instanceof Uint8Array)
  assert(salt instanceof Uint8Array)
  assert(iterations > 0 && iterations <= 2 ** 53)
  assert(bytes > 0 && bytes <= 64)

  const _password = await subtle.importKey(
    'raw',
    password,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  )

  const key = await subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-512'
    },
    _password,
    { name: 'HMAC', hash: 'SHA-512', length: bytes * 8 },
    true,
    ['sign', 'verify']
  )

  return new Uint8Array(await subtle.exportKey('raw', key))
}

/**
 * @async
 * @param  {Uint8Array} key
 * @param  {Uint8Array} data
 * @return {Promise<Uint8Array>}
 */
async function hmacSha512 (key, data) {
  assert(key instanceof Uint8Array)
  assert(data instanceof Uint8Array)

  const _key = await subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-512' },
    false,
    ['sign']
  )

  return new Uint8Array(
    await subtle.sign({ name: 'HMAC', hash: 'SHA-512' }, _key, data)
  )
}

/**
 * @async
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
async function sha256 (data) {
  return new Uint8Array(await subtle.digest('SHA-256', data))
}

async function aes256gcmEncrypt (key, iv, plaintext, aad) {
  assert(key instanceof Uint8Array)
  assert(iv instanceof Uint8Array)
  assert(plaintext instanceof Uint8Array)
  assert(aad instanceof Uint8Array)

  const _key = await subtle.importKey('raw', key, 'AES-GCM', false, [
    'encrypt'
  ])

  return new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, _key, plaintext)
  )
}

async function aes256gcmDecrypt (key, iv, ciphertext, aad) {
  assert(key instanceof Uint8Array)
  assert(iv instanceof Uint8Array)
  assert(ciphertext instanceof Uint8Array)
  assert(aad instanceof Uint8Array)

  const _key = await subtle.importKey('raw', key, 'AES-GCM', false, [
    'decrypt'
  ])

  return new Uint8Array(
    await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, _key, ciphertext)
  )
}

exports.aes256gcmDecrypt = aes256gcmDecrypt
exports.aes256gcmEncrypt = aes256gcmEncrypt
exports.hmacSha512 = hmacSha512
exports.pbkdf2Sha512 = pbkdf2Sha512
exports.randomFill = randomFill
exports.sha256 = sha256
