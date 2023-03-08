import { VegaWallet, HARDENED } from '../lib/vega-wallet.js'
import { string, toHex } from '../lib/buf.js'
import test from 'tape'

test('Vectors', async (assert) => {
  const wallet = await VegaWallet.fromMnemonic('...')
  const keys = await wallet.keyPair(HARDENED + 0)

  const sig = await keys.sign(string('hello world'))
  assert.equal(toHex(sig), 'add3d1d105b59b51e258eb8d9a876288167d5b8aabe2577e81e9a67ce46a248b9d49da88d3cd73ceb9835c44d74ca28f081cf984c89f52ace33bca65ccf64e0c')
  assert.ok(await keys.verify(sig, string('hello world')))

  const sigcid = await keys.sign(string('hello world'), 'mainnet-v1')
  assert.equal(toHex(sigcid), '27027b048ee97510e6e1fc5ea32b57f544503176787fa4fcd90876bb19fa19202b4c3f7f96c637252136cef48b701a474c477f0980cc604a397ca4ced010a109')
  assert.ok(await keys.verify(sigcid, string('hello world'), 'mainnet-v1'))
  assert.end()
})

test('Vectors 2', async (assert) => {
  const wallet = await VegaWallet.fromMnemonic('swing ceiling chaos green put insane ripple desk match tip melt usual shrug turkey renew icon parade veteran lens govern path rough page render')
  const keys = await wallet.keyPair(HARDENED + 1)

  assert.equal(keys.publicKey.toString(), 'b5fd9d3c4ad553cb3196303b6e6df7f484cf7f5331a572a45031239fd71ad8a0')

  const sig = await keys.sign(string('Je ne connaîtrai pas la peur car la peur tue l\'esprit.'))
  assert.equal(toHex(sig), '4ad1fcd911f18d0df24de692376e5beac2700322e2ab5083bcf59fd17e0a21ffd64c88e4ba79162a7d46abd9ed0a81817c1648c8d7e93ed1b1d13499b12adb08')
  assert.ok(await keys.verify(sig, string('Je ne connaîtrai pas la peur car la peur tue l\'esprit.')))

  const sigcid = await keys.sign(string('hello world'), 'mainnet-v1')
  assert.equal(toHex(sigcid), 'd1c497702086b54f98821e6cbbd9b3f3390d9531b10a23dabf155f9b5a7f371b8e49210d21ef3a399700c6d407ec50edcf4cc3cefe1657213e479d32bbaa520f')
  assert.ok(await keys.verify(sigcid, string('hello world'), 'mainnet-v1'))
  assert.end()
})
