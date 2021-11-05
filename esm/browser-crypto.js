import { n as nanoassert } from './index-a447e129.js';

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
  nanoassert(password instanceof Uint8Array);
  nanoassert(salt instanceof Uint8Array);
  nanoassert(iterations > 0 && iterations <= 2 ** 53);
  nanoassert(bytes > 0 && bytes <= 64);

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
  nanoassert(key instanceof Uint8Array);
  nanoassert(data instanceof Uint8Array);

  const _key = await scrypto.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-512' },
    false,
    ['sign']
  );

  return new Uint8Array(await scrypto.sign({ name: 'HMAC', hash: 'SHA-512' }, _key, data))
}

export { hmacSha512, pbkdf2Sha512 };
