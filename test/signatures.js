import { VegaWallet, HARDENED } from '../lib/vega-wallet.js'
import { string, toHex } from '../lib/buf.js'
import test from 'tape'

test('Vectors', async (assert) => {
  const wallet = await VegaWallet.fromMnemonic('...')
  const keys = await wallet.keyPair(HARDENED + 0)

  const sig = await keys.sign(string('hello world'))
  assert.equal(toHex(sig), 'add3d1d105b59b51e258eb8d9a876288167d5b8aabe2577e81e9a67ce46a248b9d49da88d3cd73ceb9835c44d74ca28f081cf984c89f52ace33bca65ccf64e0c')
  assert.ok(await keys.verify(sig, string('hello world')))
  assert.end()
})
