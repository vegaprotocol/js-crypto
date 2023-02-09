import { VegaWallet, HARDENED } from '@vegaprotocol/crypto/vega-wallet'
import { string, toHex } from '@vegaprotocol/crypto/buf'
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
