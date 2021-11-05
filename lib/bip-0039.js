import assert from 'nanoassert'
import * as crypto from './crypto.js'
import * as buf from './buf.js'

/** @type {Uint8Array} BIP-0039 defined salt prefix */
const BIP39_SALT_PREFIX = buf.string('mnemonic')

/** @type {number} BIP-0039 defined iterations for PBKDF2-SHA-512 */
const BIP39_ITERATIONS = 2048
/** @type {number} BIP-0039 defined number of bytes to extract for key material */
const BIP39_KEYBYTES = 64

/**
 * Derive a new seed from a BIP-0039 mnemonic. Note that no validation is
 * performed.
 * @async
 * @param  {string | Uint8Array} mnemonic - Space delimited mnemonic
 * @param  {string | Uint8Array} [password=""] - Optional password
 * @return {Promise<Uint8Array>} - 64-byte seed
 */
export async function seed (mnemonic, password = '') {
  assert(mnemonic instanceof Uint8Array || typeof mnemonic === 'string')
  assert(password instanceof Uint8Array || typeof password === 'string')

  const _password = buf.string(mnemonic)
  const salt = buf.concat(BIP39_SALT_PREFIX, buf.string(password))

  return crypto.pbkdf2Sha512(
    _password,
    salt,
    BIP39_ITERATIONS,
    BIP39_KEYBYTES
  )
}
