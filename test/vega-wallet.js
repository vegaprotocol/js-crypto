import { VegaWallet, HARDENED } from '@vegaprotocol/crypto/vega-wallet'
import test from 'tape'

test('Can recreate wallet from seed', async assert => {
  const mnemonic = 'foo bar'

  const expected = await VegaWallet.fromMnemonic(mnemonic)

  const seed = await VegaWallet.deriveSeed(mnemonic)
  const actual = await VegaWallet.fromSeed(seed)

  assert.deepEqual((await expected.keyPair(HARDENED + 1)).pk, (await actual.keyPair(HARDENED + 1)).pk)
})
