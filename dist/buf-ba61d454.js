const enc = new TextEncoder();

function string (any) {
  if (any.byteLength) return any
  return enc.encode(any)
}

function u8 (uint) {
  if (uint.byteLength) return uint
  return new Uint8Array([uint])
}

function u32be (uint) {
  if (uint.byteLength) return uint
  const ta = new Uint8Array(4);
  new DataView(ta.buffer).setUint32(0, uint, false);
  return ta
}

function concat (...uints) {
  if (uints.length === 1) return uints[0]
  const totalLength = uints.reduce((s, a) => s + a.byteLength, 0);
  const con = new Uint8Array(totalLength);

  let i = 0;
  for (const chunk of uints) {
    con.set(chunk, i);
    i += chunk.byteLength;
  }

  return con
}

function hex (buf) {
  return Array.from(buf, b => b.toString(16).padStart(2, '0')).join('')
}

export { u8 as a, concat as c, hex as h, string as s, u32be as u };
