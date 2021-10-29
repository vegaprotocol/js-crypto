import * as crypto from 'crypto'

// This is implicitly async now
export function pbkdf2Sha512 (password, salt, iterations, bytes) {
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
  return crypto.createHmac('sha512', key)
    .update(data)
    .digest()
}
