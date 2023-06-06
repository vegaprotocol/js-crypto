import assert from 'nanoassert'
import compare from 'compare'
import { wasm } from './crate.js'
import { toHex, string, concat } from './buf.js'
import { randomFill, sha256, aes256gcmEncrypt, aes256gcmDecrypt } from './crypto.js'

export const KEY_ALGORITHM = 'argon2id'
export const KEY_LENGTH = 32
export const KEY_VERSION = 0x13

export async function deriveKey (passphrase, salt, iterations, memory) {
  assert(passphrase instanceof Uint8Array)
  assert(salt instanceof Uint8Array)
  assert(iterations > 0)
  assert(memory > 0)

  return (await wasm).argon2id_kdf(passphrase, salt, iterations, memory)
}

export async function generateSalt () {
  return await randomFill(new Uint8Array(16))
}

export async function deriveSIV (key, plaintext) {
  assert(key instanceof Uint8Array)
  assert(plaintext instanceof Uint8Array)

  const tmp = concat(key, plaintext)
  const digest = await sha256(tmp)
  tmp.fill(0)

  return digest
}

export function encodeAad (obj) {
  const entries = Array.from(Object.entries(obj))
  // Sort by key
  entries.sort(([a], [b]) => compare(a, b))

  return string(JSON.stringify(entries))
}

export async function encrypt (passpharse, plaintext, kdfParams = {}) {
  assert(passpharse instanceof Uint8Array)
  assert(plaintext instanceof Uint8Array)

  kdfParams.iterations ??= 5
  kdfParams.memory ??= 64000

  assert(kdfParams.iterations > 0)
  assert(kdfParams.memory > 0)

  kdfParams.version ??= KEY_VERSION
  kdfParams.algorithm ??= KEY_ALGORITHM

  assert(kdfParams.version === KEY_VERSION)
  assert(kdfParams.algorithm === KEY_ALGORITHM)

  const salt = await generateSalt()
  const key = await deriveKey(passpharse, salt, kdfParams.iterations, kdfParams.memory)
  const aad = encodeAad(kdfParams)
  const iv = await deriveSIV(key, salt)
  const ciphertext = await aes256gcmEncrypt(key, iv, plaintext, aad)

  return { ciphertext, salt, kdfParams }
}

export async function decrypt (passphrase, ciphertext, salt, kdfParams) {
  assert(passphrase instanceof Uint8Array)
  assert(ciphertext instanceof Uint8Array)
  assert(salt instanceof Uint8Array)

  const aad = encodeAad(kdfParams)
  const key = await deriveKey(passphrase, salt, kdfParams.iterations, kdfParams.memory)
  const iv = await deriveSIV(key, salt)
  const plaintext = await aes256gcmDecrypt(key, iv, ciphertext, aad)

  return plaintext
}
