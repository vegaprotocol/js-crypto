'use strict'

const assert = require('nanoassert')
const compare = require('compare')
const crate = require('./crate.cjs')
const buf = require('./buf.cjs')
const crypto = require('./crypto.cjs')

const KEY_ALGORITHM = 'argon2id'
const KEY_LENGTH = 32
const KEY_VERSION = 0x13

async function deriveKey (passphrase, salt, iterations, memory) {
  assert(passphrase instanceof Uint8Array)
  assert(salt instanceof Uint8Array)
  assert(iterations > 0)
  assert(memory > 0)

  return (await crate.wasm).argon2id_kdf(passphrase, salt, iterations, memory)
}

async function generateSalt () {
  return await crypto.randomFill(new Uint8Array(16))
}

async function deriveSIV (key, plaintext) {
  assert(key instanceof Uint8Array)
  assert(plaintext instanceof Uint8Array)

  const tmp = buf.concat(key, plaintext)
  const digest = await crypto.sha256(tmp)
  tmp.fill(0)

  return digest
}

function encodeAad (obj) {
  const entries = Array.from(Object.entries(obj))
  // Sort by key
  entries.sort(([a], [b]) => compare(a, b))

  return buf.string(JSON.stringify(entries))
}

async function encrypt (passpharse, plaintext, kdfParams = {}) {
  assert(passpharse instanceof Uint8Array)
  assert(plaintext instanceof Uint8Array)

  kdfParams.iterations ??= 5
  kdfParams.memory ??= 256000

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
  const ciphertext = await crypto.aes256gcmEncrypt(key, iv, plaintext, aad)

  return { ciphertext, salt, kdfParams }
}

async function decrypt (passphrase, ciphertext, salt, kdfParams) {
  assert(passphrase instanceof Uint8Array)
  assert(ciphertext instanceof Uint8Array)
  assert(salt instanceof Uint8Array)

  const aad = encodeAad(kdfParams)
  const key = await deriveKey(passphrase, salt, kdfParams.iterations, kdfParams.memory)
  const iv = await deriveSIV(key, salt)
  const plaintext = await crypto.aes256gcmDecrypt(key, iv, ciphertext, aad)

  return plaintext
}

exports.KEY_ALGORITHM = KEY_ALGORITHM
exports.KEY_LENGTH = KEY_LENGTH
exports.KEY_VERSION = KEY_VERSION
exports.decrypt = decrypt
exports.deriveKey = deriveKey
exports.deriveSIV = deriveSIV
exports.encodeAad = encodeAad
exports.encrypt = encrypt
exports.generateSalt = generateSalt
