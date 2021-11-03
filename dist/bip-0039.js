import { n as nanoassert } from './index-a447e129.js';
import { pbkdf2Sha512 } from './crypto.js';
import { s as string, c as concat } from './buf-ba61d454.js';
import 'crypto';

/** @type {Uint8Array} BIP-0039 defined salt prefix */
const BIP39_SALT_PREFIX = string('mnemonic');

/** @type {number} BIP-0039 defined iterations for PBKDF2-SHA-512 */
const BIP39_ITERATIONS = 2048;
/** @type {number} BIP-0039 defined number of bytes to extract for key material */
const BIP39_KEYBYTES = 64;

/**
 * Derive a new seed from a BIP-0039 mnemonic. Note that no validation is
 * performed.
 * @param  {string | Uint8Array} mnemonic - Space delimited mnemonic
 * @param  {string | Uint8Array} [password=""] - Optional password
 * @return {Promise<Uint8Array>} - 64-byte seed
 */
async function seed (mnemonic, password = '') {
  nanoassert(mnemonic instanceof Uint8Array || typeof mnemonic === 'string');
  nanoassert(password instanceof Uint8Array || typeof password === 'string');

  const _password = string(mnemonic);
  const salt = concat(BIP39_SALT_PREFIX, string(password));

  return pbkdf2Sha512(
    _password,
    salt,
    BIP39_ITERATIONS,
    BIP39_KEYBYTES
  )
}

export { seed };
