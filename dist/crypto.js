import { n as nanoassert } from './index-a447e129.js';
import * as crypto from 'crypto';

// This is implicitly async now
function pbkdf2Sha512 (password, salt, iterations, bytes) {
  nanoassert(password instanceof Uint8Array);
  nanoassert(salt instanceof Uint8Array);
  nanoassert(iterations > 0 && iterations <= 2 ** 53);
  nanoassert(bytes > 0 && bytes <= 64);

  return new Promise((resolve, reject) => {
    crypto.pbkdf2(
      password,
      salt,
      iterations,
      bytes,
      'sha512',
      (err, seed) => {
        if (err) return reject(err)
        resolve(seed);
      }
    );
  })
}

// This one is async to keep the same API as the browser SubtleCrypto
async function hmacSha512 (key, data) {
  nanoassert(key instanceof Uint8Array);
  nanoassert(data instanceof Uint8Array);

  return crypto.createHmac('sha512', key)
    .update(data)
    .digest()
}

export { hmacSha512, pbkdf2Sha512 };
