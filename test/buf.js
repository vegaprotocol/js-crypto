import { base64, fromBase64, string, toString } from '../lib/buf.js'
import { test } from 'brittle'

test('base64 identity', assert => {
  const str = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non risus. Suspendisse lectus tortor, dignissim sit amet, adipiscing nec, ultricies sed, dolor.'
  const b64 = 'TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gU2VkIG5vbiByaXN1cy4gU3VzcGVuZGlzc2UgbGVjdHVzIHRvcnRvciwgZGlnbmlzc2ltIHNpdCBhbWV0LCBhZGlwaXNjaW5nIG5lYywgdWx0cmljaWVzIHNlZCwgZG9sb3Iu'

  assert.is(base64(string(str)), b64)

  const buf = string(str)
  assert.is(toString(fromBase64(base64(buf))), str)
})
