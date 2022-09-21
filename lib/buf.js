const enc = new TextEncoder()

/**
 * Convert a string to Uint8Array
 * @param  {string | Uint8Array} any
 * @return {Uint8Array}
 */
export function string (any) {
  if (any instanceof Uint8Array) return any
  return enc.encode(any)
}

/**
 * Convert a uint8 [0, 255] to a Uint8Array
 * @param  {number | Uint8Array} uint
 * @return {Uint8Array}
 */
export function u8 (uint) {
  if (uint instanceof Uint8Array) return uint
  return new Uint8Array([uint])
}

/**
 * Convert a u32 [0, 0xffffffff] to a Uint8Array in Big Endian encoding
 * @param  {number | Uint8Array} uint
 * @return {Uint8Array}
 */
export function u32be (uint) {
  if (uint instanceof Uint8Array) return uint
  const ta = new Uint8Array(4)
  new DataView(ta.buffer).setUint32(0, uint, false)
  return ta
}

/**
 * Concatenate a number of Uint8Arrays to a single Uint8Array
 * @param  {Uint8Array[]} uints
 * @return {Uint8Array}
 */
export function concat (...uints) {
  if (uints.length === 1) return uints[0]
  const totalLength = uints.reduce((s, a) => s + a.byteLength, 0)
  const con = new Uint8Array(totalLength)

  let i = 0
  for (const chunk of uints) {
    con.set(chunk, i)
    i += chunk.byteLength
  }

  return con
}

/**
 * Encode Uint8Array as hex string
 * @param  {Uint8Array} buf
 * @return {string}
 */
export function toHex (buf) {
  return Array.from(buf, b => b.toString(16).padStart(2, '0')).join('')
}
