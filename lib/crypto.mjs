import assert from 'nanoassert'
import * as crypto from 'crypto'

// This is implicitly async now
export function pbkdf2Sha512 (password, salt, iterations, bytes) {
  assert(password instanceof Uint8Array)
  assert(salt instanceof Uint8Array)
  assert(iterations > 0 && iterations <= 2 ** 53)
  assert(bytes > 0 && bytes <= 64)

  return new Promise((resolve, reject) => {
    crypto.pbkdf2(
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

// This one is async to keep the same API as the browser SubtleCrypto
export async function hmacSha512 (key, data) {
  assert(key instanceof Uint8Array)
  assert(data instanceof Uint8Array)

  return crypto.createHmac('sha512', key)
    .update(data)
    .digest()
}
