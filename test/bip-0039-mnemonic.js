import { test } from 'brittle'
import * as bip0039words from '../lib/bip-0039/mnemonic.js'

test('entropy', async assert => {
  {
    const entropy = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'legal winner thank year wave sausage worth useful legal winner thank yellow'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x9e, 0x88, 0x5d, 0x95, 0x2a, 0xd3, 0x62, 0xca, 0xeb, 0x4e, 0xfe, 0x34, 0xa8, 0xe9, 0x1b, 0xd2])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x66, 0x10, 0xb2, 0x59, 0x67, 0xcd, 0xcc, 0xa9, 0xd5, 0x98, 0x75, 0xf5, 0xcb, 0x50, 0xb0, 0xea, 0x75, 0x43, 0x33, 0x11, 0x86, 0x9e, 0x93, 0x0b])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x68, 0xa7, 0x9e, 0xac, 0xa2, 0x32, 0x48, 0x73, 0xea, 0xcc, 0x50, 0xcb, 0x9c, 0x6e, 0xca, 0x8c, 0xc6, 0x8e, 0xa5, 0xd9, 0x36, 0xf9, 0x87, 0x87, 0xc6, 0x0c, 0x7e, 0xbc, 0x74, 0xe6, 0xce, 0x7c])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0xc0, 0xba, 0x5a, 0x8e, 0x91, 0x41, 0x11, 0x21, 0x0f, 0x2b, 0xd1, 0x31, 0xf3, 0xd5, 0xe0, 0x8d])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'scheme spot photo card baby mountain device kick cradle pact join borrow'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x6d, 0x9b, 0xe1, 0xee, 0x6e, 0xbd, 0x27, 0xa2, 0x58, 0x11, 0x5a, 0xad, 0x99, 0xb7, 0x31, 0x7b, 0x9c, 0x8d, 0x28, 0xb6, 0xd7, 0x64, 0x31, 0xc3])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x9f, 0x6a, 0x28, 0x78, 0xb2, 0x52, 0x07, 0x99, 0xa4, 0x4e, 0xf1, 0x8b, 0xc7, 0xdf, 0x39, 0x4e, 0x70, 0x61, 0xa2, 0x24, 0xd2, 0xc3, 0x3c, 0xd0, 0x15, 0xb1, 0x57, 0xd7, 0x46, 0x86, 0x98, 0x63])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x23, 0xdb, 0x81, 0x60, 0xa3, 0x1d, 0x3e, 0x0d, 0xca, 0x36, 0x88, 0xed, 0x94, 0x1a, 0xdb, 0xf3])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'cat swing flag economy stadium alone churn speed unique patch report train'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x81, 0x97, 0xa4, 0xa4, 0x7f, 0x04, 0x25, 0xfa, 0xea, 0xa6, 0x9d, 0xee, 0xbc, 0x05, 0xca, 0x29, 0xc0, 0xa5, 0xb5, 0xcc, 0x76, 0xce, 0xac, 0xc0])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0x06, 0x6d, 0xca, 0x1a, 0x2b, 0xb7, 0xe8, 0xa1, 0xdb, 0x28, 0x32, 0x14, 0x8c, 0xe9, 0x93, 0x3e, 0xea, 0x0f, 0x3a, 0xc9, 0x54, 0x8d, 0x79, 0x31, 0x12, 0xd9, 0xa9, 0x5c, 0x94, 0x07, 0xef, 0xad])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0xf3, 0x0f, 0x8c, 0x1d, 0xa6, 0x65, 0x47, 0x8f, 0x49, 0xb0, 0x01, 0xd9, 0x4c, 0x5f, 0xc4, 0x52])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'vessel ladder alter error federal sibling chat ability sun glass valve picture'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0xc1, 0x0e, 0xc2, 0x0d, 0xc3, 0xcd, 0x9f, 0x65, 0x2c, 0x7f, 0xac, 0x2f, 0x12, 0x30, 0xf7, 0xa3, 0xc8, 0x28, 0x38, 0x9a, 0x14, 0x39, 0x2f, 0x05])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
  {
    const entropy = new Uint8Array([0xf5, 0x85, 0xc1, 0x1a, 0xec, 0x52, 0x0d, 0xb5, 0x7d, 0xd3, 0x53, 0xc6, 0x95, 0x54, 0xb2, 0x1a, 0x89, 0xb2, 0x0f, 0xb0, 0x65, 0x09, 0x66, 0xfa, 0x0a, 0x9d, 0x6f, 0x74, 0xfd, 0x98, 0x9d, 0x8f])
    const mnemonic = await bip0039words.toMnemonic(await bip0039words.checksum(entropy))
    const expected = 'void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold'
    assert.is(mnemonic.join(' '), expected)
    assert.ok(await bip0039words.validate(mnemonic))
  }
})

test('importing', async (assert) => {
  const N = 1000
  for (let i = 0; i < N; i++) {
    const entropy = await bip0039words.entropy(128)
    const mnemonic = await bip0039words.toMnemonic(entropy)
    const valid = await bip0039words.validate(mnemonic)
    if (valid === false) return assert.fail('Invalid phrase')
  }
  for (let i = 0; i < N; i++) {
    const entropy = await bip0039words.entropy(160)
    const mnemonic = await bip0039words.toMnemonic(entropy)
    const valid = await bip0039words.validate(mnemonic)
    if (valid === false) return assert.fail('Invalid phrase')
  } for (let i = 0; i < N; i++) {
    const entropy = await bip0039words.entropy(192)
    const mnemonic = await bip0039words.toMnemonic(entropy)
    const valid = await bip0039words.validate(mnemonic)
    if (valid === false) return assert.fail('Invalid phrase')
  }
  for (let i = 0; i < N; i++) {
    const entropy = await bip0039words.entropy(224)
    const mnemonic = await bip0039words.toMnemonic(entropy)
    const valid = await bip0039words.validate(mnemonic)
    if (valid === false) return assert.fail('Invalid phrase')
  }

  for (let i = 0; i < N; i++) {
    const entropy = await bip0039words.entropy(256)
    const mnemonic = await bip0039words.toMnemonic(entropy)
    const valid = await bip0039words.validate(mnemonic)
    if (valid === false) return assert.fail('Invalid phrase')
  }
})

test('import error cases', async (assert) => {
  await assert.exception(bip0039words.validate('abandon abandon ab'), /phrase must be 12, 15, 18, 21 or 24 words/)
  await assert.exception(bip0039words.validate('scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango kongress clump'), /word "kongress" is not in the wordlist/)
  await assert.exception(bip0039words.validate('scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress mango'), /checksum mismatch, phrase corrupted. The last word is a checksum/)
})
