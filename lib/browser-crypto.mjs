const scrypto = window.crypto.subtle

export async function pbkdf2Sha512 (password, salt, iterations, bytes, hash) {
  const _password = await scrypto.importKey(
    'raw',
    password,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  )

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
  )

  return new Uint8Array(await scrypto.exportKey('raw', key))
}

export async function hmacSha512 (key, data) {
  const _key = await scrypto.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-512' },
    false,
    ['sign']
  )

  return new Uint8Array(await scrypto.sign({ name: 'HMAC', hash: 'SHA-512' }, _key, data))
}
