import { base64, toBase64, string, toString, hex, toHex } from '../lib/buf.js'
import { test } from 'brittle'

test('base64 identity', assert => {
  const str = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non risus. Suspendisse lectus tortor, dignissim sit amet, adipiscing nec, ultricies sed, dolor.'
  const b64 = 'TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gU2VkIG5vbiByaXN1cy4gU3VzcGVuZGlzc2UgbGVjdHVzIHRvcnRvciwgZGlnbmlzc2ltIHNpdCBhbWV0LCBhZGlwaXNjaW5nIG5lYywgdWx0cmljaWVzIHNlZCwgZG9sb3Iu'

  assert.is(toBase64(string(str)), b64)

  const buf = string(str)
  assert.is(toString(base64(toBase64(buf))), str)
})

test('hex identity', assert => {
  const str = 'foo bar'
  const h = '666f6f20626172'

  assert.is(toHex(string(str)), h)

  const buf = string(str)
  assert.is(toString(hex(toHex(buf))), str)
})
