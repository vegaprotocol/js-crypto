'use strict'

const enc = new TextEncoder()

/**
 * Convert a string to Uint8Array
 * @param  {string | Uint8Array} any
 * @return {Uint8Array}
 */
function string (any) {
  if (any instanceof Uint8Array) return any
  return enc.encode(any)
}

/**
 * Convert a uint8 [0, 255] to a Uint8Array
 * @param  {number | Uint8Array} uint
 * @return {Uint8Array}
 */
function u8 (uint) {
  if (uint instanceof Uint8Array) return uint
  return new Uint8Array([uint])
}

/**
 * Convert a u32 [0, 0xffffffff] to a Uint8Array in Big Endian encoding
 * @param  {number | Uint8Array} uint
 * @return {Uint8Array}
 */
function u32be (uint) {
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
function concat (...uints) {
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
function toHex (buf) {
  return Array.from(buf, b => b.toString(16).padStart(2, '0')).join('')
}

const dec = new TextDecoder()

/**
 * Decode Uint8Array as string
 * @param  {Uint8Array} buf
 * @return {string}
 */
function toString (buf) {
  return dec.decode(buf)
}

// Modified from the b64 encoder emitted by wasmbindgen
const b64Lookup = [62, 0, 0, 0, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51]
const asciiLookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
function getBase64Code (charCode) {
  return b64Lookup[charCode - 43]
}

/**
 * Decode a base64 string to Uint8Array
 * @param  {string} str
 * @return {Uint8Array}
 */
function fromBase64 (str) {
  const missingOctets = str.endsWith('==') ? 2 : str.endsWith('=') ? 1 : 0
  const n = str.length
  const result = new Uint8Array(3 * (n / 4))
  let buffer

  for (let i = 0, j = 0; i < n; i += 4, j += 3) {
    buffer =
      getBase64Code(str.charCodeAt(i)) << 18 |
      getBase64Code(str.charCodeAt(i + 1)) << 12 |
      getBase64Code(str.charCodeAt(i + 2)) << 6 |
      getBase64Code(str.charCodeAt(i + 3))
    result[j] = buffer >> 16
    result[j + 1] = (buffer >> 8) & 0xFF
    result[j + 2] = buffer & 0xFF
  }

  return result.subarray(0, result.length - missingOctets)
}

/**
 * Encode a Uint8Array to base64 string
 * @param  {Uint8Array} buf
 * @return {string}
 */
function base64 (buf) {
  let result = ''; let i; const l = buf.length
  for (i = 2; i < l; i += 3) {
    result += asciiLookup[buf[i - 2] >> 2]
    result += asciiLookup[((buf[i - 2] & 0x03) << 4) | (buf[i - 1] >> 4)]
    result += asciiLookup[((buf[i - 1] & 0x0F) << 2) | (buf[i] >> 6)]
    result += asciiLookup[buf[i] & 0x3F]
  }
  if (i === l + 1) { // 1 octet yet to write
    result += asciiLookup[buf[i - 2] >> 2]
    result += asciiLookup[(buf[i - 2] & 0x03) << 4]
    result += '=='
  }
  if (i === l) { // 2 octets yet to write
    result += asciiLookup[buf[i - 2] >> 2]
    result += asciiLookup[((buf[i - 2] & 0x03) << 4) | (buf[i - 1] >> 4)]
    result += asciiLookup[(buf[i - 1] & 0x0F) << 2]
    result += '='
  }
  return result
}

exports.base64 = base64
exports.concat = concat
exports.fromBase64 = fromBase64
exports.string = string
exports.toHex = toHex
exports.toString = toString
exports.u32be = u32be
exports.u8 = u8
