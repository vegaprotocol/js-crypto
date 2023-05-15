import { test } from 'brittle'
import { aes256gcmEncrypt, aes256gcmDecrypt, randomFill } from '../lib/crypto.js'
import { string } from '../lib/buf.js'
import { encrypt, decrypt } from '../lib/encryption.js'

test('aes256gcm identity', async assert => {
  const key = await randomFill(new Uint8Array(32))

  const nonce = await randomFill(new Uint8Array(12))
  const plaintext = string('hello world')
  const ciphertext = await aes256gcmEncrypt(key, nonce, plaintext, new Uint8Array([]))
  const decrypted = await aes256gcmDecrypt(key, nonce, ciphertext, new Uint8Array([]))
  assert.alike(Array.from(plaintext), Array.from(decrypted))
})

test('aes256gcm static', async assert => {
  const key = new Uint8Array([
    251, 106, 195, 60, 58, 85, 18, 243,
    11, 101, 228, 7, 119, 15, 114, 190,
    223, 82, 84, 98, 244, 29, 123, 172,
    66, 45, 173, 89, 121, 55, 133, 92
  ])

  const iv = new Uint8Array([
    138, 143, 84, 188, 99,
    40, 83, 141, 237, 223,
    238, 142
  ])

  const plaintext = string('hello world')
  const ciphertext = await aes256gcmEncrypt(key, iv, plaintext, new Uint8Array([]))
  assert.alike([
    110, 115, 170, 120, 124, 118, 137,
    124, 112, 43, 156, 188, 17, 20,
    108, 90, 149, 202, 66, 97, 74,
    152, 85, 190, 208, 208, 172
  ], Array.from(ciphertext))
  const decrypted = await aes256gcmDecrypt(key, iv, ciphertext, new Uint8Array([]))
  assert.alike(Array.from(plaintext), Array.from(decrypted))
})

test('encrypt/decrypt', async assert => {
  const passphrase = string('this is a random passphrase')
  const plaintext = string('hello world')
  const { ciphertext, salt, kdfParams } = await encrypt(passphrase, plaintext)
  assert.pass('encrypted')
  const decrypted = await decrypt(passphrase, ciphertext, salt, kdfParams)
  assert.alike(Array.from(plaintext), Array.from(decrypted))
})
